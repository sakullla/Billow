//! ShadowQUIC `udp-over-stream` recovery against a controlled QUIC peer.
//!
//! The pinned ShadowQUIC listener does not expose a way to close one client uni
//! stream mid-association, so this peer closes the client's stream and control
//! send halves explicitly. The kernel must drop the cached uni stream and open
//! a new one, and it must rebuild the whole association (control stream +
//! re-registered ids) when the control stream is closed.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use billow_kernel::outbound::shadowquic::ShadowQuicUdp;
use billow_kernel::outbound::tls::{quic_client_config, ClientTls};
use billow_kernel::outbound::Target;
use billow_kernel::proxies::TlsSettings;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::CertificateDer;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

struct Cert {
    der: Vec<u8>,
    key: PathBuf,
    dir: PathBuf,
}

impl Drop for Cert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn make_cert() -> Cert {
    let dir = std::env::temp_dir().join(format!(
        "billow-shadowquic-stream-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("key.pem");
    let cert = dir.join("cert.pem");
    let status = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl is required for the shadowquic stream peer");
    assert!(status.success(), "openssl failed");
    let pem = std::fs::read_to_string(&cert).unwrap();
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .as_ref()
        .to_vec();
    Cert { der, key, dir }
}

fn server_config(cert: &Cert) -> quinn::ServerConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der.clone())],
            rustls_pemfile::private_key(&mut std::io::BufReader::new(
                std::fs::File::open(&cert.key).unwrap(),
            ))
            .unwrap()
            .unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(config).unwrap()))
}

async fn read_u16(recv: &mut quinn::RecvStream) -> io::Result<u16> {
    let mut raw = [0u8; 2];
    recv.read_exact(&mut raw)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(u16::from_be_bytes(raw))
}

async fn read_packet(recv: &mut quinn::RecvStream) -> io::Result<Vec<u8>> {
    let length = read_u16(recv).await? as usize;
    let mut payload = vec![0u8; length];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(payload)
}

fn io_err(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

async fn read_control_entry(recv: &mut quinn::RecvStream) -> io::Result<(Target, u16)> {
    let kind = recv.read_u8().await.map_err(io_err)?;
    let host = match kind {
        0x01 => {
            let mut raw = [0u8; 4];
            recv.read_exact(&mut raw).await.map_err(io_err)?;
            std::net::Ipv4Addr::from(raw).to_string()
        }
        0x04 => {
            let mut raw = [0u8; 16];
            recv.read_exact(&mut raw).await.map_err(io_err)?;
            std::net::Ipv6Addr::from(raw).to_string()
        }
        0x03 => {
            let len = recv.read_u8().await.map_err(io_err)? as usize;
            let mut name = vec![0u8; len];
            recv.read_exact(&mut name).await.map_err(io_err)?;
            String::from_utf8(name).map_err(|_| io::Error::other("domain"))?
        }
        other => return Err(io::Error::other(format!("address type {other}"))),
    };
    let port = read_u16(recv).await?;
    let id = read_u16(recv).await?;
    Ok((Target { host, port }, id))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_over_stream_reopens_a_stopped_uni_stream_and_control() {
    let cert = make_cert();
    let server_endpoint =
        quinn::Endpoint::server(server_config(&cert), SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("server endpoint");
    let server_addr = server_endpoint.local_addr().unwrap();
    let (events_tx, mut events) = mpsc::unbounded_channel::<String>();
    let server_events = events_tx.clone();

    tokio::spawn(async move {
        let incoming = match server_endpoint.accept().await {
            Some(incoming) => incoming,
            None => return,
        };
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(e) => {
                let _ = server_events.send(format!("accept: {e}"));
                return;
            }
        };
        let result: io::Result<()> = async {
            let (control_send, mut control_recv) = connection
                .accept_bi()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let command = control_recv.read_u8().await.map_err(io_err)?;
            let mut unspecified = [0u8; 7];
            control_recv
                .read_exact(&mut unspecified)
                .await
                .map_err(io_err)?;
            let _ = server_events.send(format!("control-command:{command}"));

            // Phase 1: accept the first destination stream, then stop it.
            let mut first = connection
                .accept_uni()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let first_id = read_u16(&mut first).await?;
            let first_payload = read_packet(&mut first).await?;
            let _ = server_events.send(format!(
                "uni:{first_id}:{}",
                String::from_utf8_lossy(&first_payload)
            ));
            first.stop(0u32.into()).ok();

            // The client notices the stop on its next write and reopens a new
            // uni stream without touching the control stream.
            let mut second = connection
                .accept_uni()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let second_id = read_u16(&mut second).await?;
            let second_payload = read_packet(&mut second).await?;
            let _ = server_events.send(format!(
                "uni:{second_id}:{}",
                String::from_utf8_lossy(&second_payload)
            ));

            // Phase 2: close the control send half. The client's next new
            // target must rebuild the association.
            control_recv.stop(0u32.into()).ok();
            drop(control_recv);
            drop(control_send);

            let (mut new_control_send, mut new_control_recv) = connection
                .accept_bi()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let new_command = new_control_recv.read_u8().await.map_err(io_err)?;
            let mut unspecified = [0u8; 7];
            new_control_recv
                .read_exact(&mut unspecified)
                .await
                .map_err(io_err)?;
            let _ = server_events.send(format!("control-command:{new_command}"));
            // The client re-registers the old target and adds the new one.
            let (old_target, old_id) = read_control_entry(&mut new_control_recv).await?;
            let (new_target, new_id) = read_control_entry(&mut new_control_recv).await?;
            let _ = server_events.send(format!(
                "control:{}:{}:{old_id}",
                old_target.host, old_target.port
            ));
            let _ = server_events.send(format!(
                "control:{}:{}:{new_id}",
                new_target.host, new_target.port
            ));

            let mut third = connection
                .accept_uni()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let third_id = read_u16(&mut third).await?;
            let third_payload = read_packet(&mut third).await?;
            let _ = server_events.send(format!(
                "uni:{third_id}:{}",
                String::from_utf8_lossy(&third_payload)
            ));
            let _ = new_control_send.finish();
            Ok(())
        }
        .await;
        if let Err(e) = result {
            let _ = server_events.send(format!("peer-error:{e}"));
        }
    });

    let tls = ClientTls::new(&[]);
    let settings = TlsSettings {
        sni: Some("localhost".to_string()),
        skip_cert_verify: true,
        alpn: vec!["h3".to_string()],
    };
    let rustls_config =
        quic_client_config(&settings, &tls, &["h3".to_string()], true).expect("client TLS");
    let crypto = QuicClientConfig::try_from(rustls_config).expect("quic crypto");
    let client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let client_endpoint =
        quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).expect("client endpoint");
    let connection = client_endpoint
        .connect_with(client_config, server_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");
    let mut association =
        ShadowQuicUdp::from_connection_for_test(connection, client_endpoint, true, 1400)
            .await
            .expect("association");

    expect_event(&mut events, "control-command:4").await;
    let target_one = Target {
        host: "127.0.0.1".to_string(),
        port: 10001,
    };
    let target_two = Target {
        host: "127.0.0.1".to_string(),
        port: 10002,
    };

    association
        .send(&target_one, b"one")
        .await
        .expect("first send");
    expect_event(&mut events, "uni:0:one").await;
    // Let the STOP_SENDING reach the client before writing again.
    tokio::time::sleep(Duration::from_millis(300)).await;
    association
        .send(&target_one, b"two")
        .await
        .expect("reopened uni send");
    expect_event(&mut events, "uni:0:two").await;

    // The peer closed the control stream; a new destination must reopen it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    association
        .send(&target_two, b"three")
        .await
        .expect("rebuilt control send");
    expect_event(&mut events, "control-command:4").await;
    expect_event(&mut events, "control:127.0.0.1:10001:0").await;
    expect_event(&mut events, "control:127.0.0.1:10002:1").await;
    expect_event(&mut events, "uni:1:three").await;

    drop(association);
}

async fn expect_event(events: &mut mpsc::UnboundedReceiver<String>, expected: &str) {
    for _ in 0..200 {
        match tokio::time::timeout(Duration::from_millis(50), events.recv()).await {
            Ok(Some(event)) if event == expected => return,
            Ok(Some(event)) => panic!("expected {expected:?}, got {event:?}"),
            Ok(None) => panic!("peer closed before {expected:?}"),
            Err(_) => continue,
        }
    }
    panic!("timed out waiting for {expected:?}");
}
