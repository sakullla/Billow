//! Independent SSR server interop.
//!
//! The default suite's SSR peer shares the Rust `SsrStream` implementation with
//! the client, so it proves framing only. This ignored test uses the Go server
//! in `tool/kernel-compat/peers/ssr-server`, which is written against the
//! pinned `transport/shadowsocks/shadowstream` package, to verify IV exchange,
//! the encrypted SOCKS address and the relay with an independent implementation.
//!
//! Controlled entry point (builds the Go server first):
//!
//! ```sh
//! tool/kernel-compat/family-peers.sh
//! ```
//!
//! Without `KC_SSR_PEER_BIN` the cases print SKIP and never pass.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use billow_kernel::{Kernel, Limits};

struct SsrPeer {
    child: Child,
    addr: SocketAddr,
}

impl Drop for SsrPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buffer = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buffer) {
                    if n == 0 || stream.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn start_peer(cipher: &str, password: &str) -> SsrPeer {
    let bin = std::env::var_os("KC_SSR_PEER_BIN").expect("KC_SSR_PEER_BIN");
    let port = free_port();
    let mut child = Command::new(bin)
        .args([
            "-listen",
            &format!("127.0.0.1:{port}"),
            "-cipher",
            cipher,
            "-password",
            password,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ssr peer");
    let stdout = child.stdout.take().expect("peer stdout");
    let mut lines = BufReader::new(stdout).lines();
    let ready = lines.next().expect("peer READY line").expect("peer READY");
    assert!(ready.starts_with("READY "), "peer said: {ready}");
    SsrPeer {
        child,
        addr: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}

fn start_kernel(peer_port: u16, cipher: &str, password: &str) -> (Kernel, SocketAddr) {
    let port = free_port();
    let yaml = format!(
        "mixed-port: {port}\nlog-level: warn\nproxies:\n  - {{name: p, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: {cipher}, password: {password}, protocol: origin, obfs: plain}}\nrules:\n  - 'MATCH,p'\n"
    );
    let (kernel, _) = Kernel::start_from_yaml(&yaml, None, Limits::default()).unwrap();
    let listen = kernel.listen_addr();
    (kernel, listen)
}

fn connect(proxy: SocketAddr, target: &str, marker: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    if !status.starts_with("HTTP/1.1 200") {
        return Err(std::io::Error::other(status));
    }
    stream.write_all(marker)?;
    let mut back = vec![0u8; marker.len()];
    stream.read_exact(&mut back)?;
    Ok(back)
}

#[test]
#[ignore = "needs the Go SSR server: run tool/kernel-compat/family-peers.sh"]
fn ssr_go_server_relays_the_client_frames() {
    let Some(_) = std::env::var_os("KC_SSR_PEER_BIN") else {
        eprintln!("SKIP ssr_go_server_relays_the_client_frames (set KC_SSR_PEER_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let echo = spawn_echo();
    let peer = start_peer("aes-256-cfb", "ssr-go-pass");
    let (mut kernel, proxy) = start_kernel(peer.addr.port(), "aes-256-cfb", "ssr-go-pass");
    let back = connect(proxy, &format!("127.0.0.1:{echo}"), b"independent-ssr-go")
        .expect("tunnel through the Go SSR server");
    assert_eq!(back, b"independent-ssr-go".to_vec());
    kernel.stop().unwrap();
}

#[test]
#[ignore = "needs the Go SSR server: run tool/kernel-compat/family-peers.sh"]
fn ssr_go_server_rejects_a_wrong_password() {
    let Some(_) = std::env::var_os("KC_SSR_PEER_BIN") else {
        eprintln!("SKIP ssr_go_server_rejects_a_wrong_password (set KC_SSR_PEER_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let echo = spawn_echo();
    let peer = start_peer("aes-256-cfb", "right-password");
    let (mut kernel, proxy) = start_kernel(peer.addr.port(), "aes-256-cfb", "wrong-password");
    let error = connect(proxy, &format!("127.0.0.1:{echo}"), b"must-not-arrive");
    assert!(error.is_err(), "wrong password must not relay: {error:?}");
    kernel.stop().unwrap();
}
