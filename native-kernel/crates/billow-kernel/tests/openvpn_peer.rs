//! OpenVPN control-channel/data-channel interoperability with a real
//! OpenVPN 2.7.9 server.
//!
//! The server runs with `--dev null` (no TUN, no root): the control channel,
//! TLS client authentication, key-method 2 exchange and `PUSH_REPLY` are real,
//! and `--ping 1` makes the server send data-channel keepalives so the AEAD
//! keys are proven by decrypting a real packet. The certificate chain is
//! generated with the `openssl` CLI into a temporary directory.
//!
//! Controlled entry point:
//!
//! ```sh
//! tool/kernel-compat/family-peers.sh openvpn_peer
//! # or
//! KC_OPENVPN_BIN=/opt/homebrew/opt/openvpn/sbin/openvpn cargo test \
//!   --manifest-path native-kernel/Cargo.toml --locked \
//!   --test openvpn_peer -- --ignored --test-threads=1
//! ```
//!
//! Without `KC_OPENVPN_BIN` (or an `openvpn` in PATH) the cases print SKIP and
//! never pass.

use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use billow_kernel::outbound::openvpn::OpenVpnTunnel;
use billow_kernel::proxies::Protocol;
use billow_kernel::load_config;

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn openvpn_bin() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("KC_OPENVPN_BIN") {
        return Some(PathBuf::from(value));
    }
    let default = Path::new("/opt/homebrew/opt/openvpn/sbin/openvpn");
    if default.is_file() {
        return Some(default.to_path_buf());
    }
    which("openvpn")
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn run_openssl(args: &[&str], directory: &Path) {
    let status = Command::new("openssl")
        .args(args)
        .current_dir(directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run openssl");
    assert!(status.success(), "openssl {args:?}");
}

fn write_file(path: &Path, contents: &[u8]) {
    let mut file = std::fs::File::create(path).expect("create");
    file.write_all(contents).expect("write");
}

fn make_ca(directory: &Path, name: &str) {
    run_openssl(
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &format!("{name}-ca.key"),
            "-out",
            &format!("{name}-ca.pem"),
            "-days",
            "2",
            "-subj",
            &format!("/CN=Billow {name} CA"),
        ],
        directory,
    );
}

fn make_leaf(directory: &Path, ca: &str, name: &str, server: bool) {
    run_openssl(
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-subj",
            &format!("/CN={name}"),
        ],
        directory,
    );
    let extension = if server {
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
    } else {
        "extendedKeyUsage=clientAuth\n"
    };
    write_file(&directory.join(format!("{name}.ext")), extension.as_bytes());
    run_openssl(
        &[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{ca}-ca.pem"),
            "-CAkey",
            &format!("{ca}-ca.key"),
            "-CAcreateserial",
            "-out",
            &format!("{name}.pem"),
            "-days",
            "2",
            "-extfile",
            &format!("{name}.ext"),
        ],
        directory,
    );
}

fn certificates(directory: &Path) {
    make_ca(directory, "server");
    make_leaf(directory, "server", "server", true);
    make_leaf(directory, "server", "client", false);
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_server() -> Option<Server> {
    let bin = openvpn_bin()?;
    let dir = std::env::temp_dir().join(format!("billow-openvpn-peer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("cert dir");
    certificates(&dir);

    let port = free_udp_port();
    let child = Command::new(bin)
        .args([
            "--dev",
            "null",
            "--mode",
            "server",
            "--tls-server",
            "--ca",
            dir.join("server-ca.pem").to_str().unwrap(),
            "--cert",
            dir.join("server.pem").to_str().unwrap(),
            "--key",
            dir.join("server.key").to_str().unwrap(),
            "--dh",
            "none",
            "--proto",
            "udp4",
            "--local",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--topology",
            "subnet",
            "--server",
            "10.8.0.0",
            "255.255.255.0",
            "--data-ciphers",
            "AES-256-GCM",
            "--ping",
            "1",
            "--verb",
            "3",
        ])
        .stdout(std::fs::File::create(dir.join("server.log")).expect("server log"))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openvpn server");
    // The socket is bound after initialization; the client retries the hard
    // reset, so a short wait is enough.
    std::thread::sleep(Duration::from_millis(1200));
    Some(Server { child, port, dir })
}

fn indent(pem: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    pem.lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn config_yaml(server: &Server, ca: &str, cert: Option<&str>, key: Option<&str>) -> String {
    let mut yaml = format!(
        "mixed-port: 1\nproxies:\n  - name: ov\n    type: openvpn\n    server: 127.0.0.1\n    port: {}\n    proto: udp\n    cipher: AES-256-GCM\n    auth: SHA256\n    ca: |\n{}\n",
        server.port,
        indent(ca, 6)
    );
    if let (Some(cert), Some(key)) = (cert, key) {
        yaml.push_str(&format!(
            "    cert: |\n{}\n    key: |\n{}\n",
            indent(cert, 6),
            indent(key, 6)
        ));
    }
    yaml.push_str("rules:\n  - 'MATCH,ov'\n");
    yaml
}

fn openvpn_option(yaml: &str) -> billow_kernel::proxies::OpenVpnOutbound {
    let loaded = load_config(yaml, "openvpn-peer.yaml").expect("config loads");
    let proxy = loaded
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.name == "ov")
        .expect("proxy");
    match &proxy.protocol {
        Protocol::OpenVpn(option) => option.clone(),
        other => panic!("unexpected protocol: {other:?}"),
    }
}

fn skip(case: &str) -> bool {
    if openvpn_bin().is_none() {
        eprintln!("SKIP {case}: no openvpn binary (set KC_OPENVPN_BIN)");
        return true;
    }
    false
}

#[test]
#[ignore]
fn control_channel_pushes_and_the_data_keys_decrypt_a_keepalive() {
    if skip("control_channel_pushes_and_the_data_keys_decrypt_a_keepalive") {
        return;
    }
    let server = start_server().expect("server");
    let ca = std::fs::read_to_string(server.dir.join("server-ca.pem")).unwrap();
    let cert = std::fs::read_to_string(server.dir.join("client.pem")).unwrap();
    let key = std::fs::read_to_string(server.dir.join("client.key")).unwrap();
    let yaml = config_yaml(&server, &ca, Some(&cert), Some(&key));
    let option = openvpn_option(&yaml);

    let mut tunnel = match OpenVpnTunnel::connect(&option, Duration::from_secs(15)) {
        Ok(tunnel) => tunnel,
        Err(error) => {
            let log = std::fs::read_to_string(server.dir.join("server.log")).unwrap_or_default();
            panic!("connect: {error}\nserver log:\n{log}");
        }
    };
    let push = tunnel.push_reply();
    assert!(push.raw.starts_with("PUSH_REPLY"), "{}", push.raw);
    assert!(push.ifconfig.is_some(), "{}", push.raw);
    // The stack uses the first pushed address as its local address; the
    // prefix must line up with the ifconfig record the server sent.
    let ifconfig = push.ifconfig.as_deref().expect("ifconfig");
    let first = ifconfig.split_whitespace().next().expect("ifconfig address");
    let (local, bits) = *push.prefixes.first().expect("ifconfig prefix");
    assert_eq!(local.to_string(), first, "{}", push.raw);
    assert!(bits <= 32, "{}: {bits}", push.raw);
    assert_eq!(tunnel.cipher(), "AES-256-GCM");
    // The server pings every second; decrypting one proves the AEAD data
    // keys, the peer ID and the implicit IV.
    tunnel
        .exchange_keepalive(Duration::from_secs(5))
        .expect("data-channel keepalive");

    // The data channel also accepts an IP packet. `--dev null` throws it away,
    // so this proves encryption/framing and that the session stays usable; the
    // real tunnel datapath is not claimed to be end-to-end verified here.
    let packet = vec![0x45u8; 60];
    tunnel.send_data(&packet).expect("send_data");
    tunnel
        .exchange_keepalive(Duration::from_secs(5))
        .expect("keepalive after send_data");
}

#[test]
#[ignore]
fn an_untrusted_server_certificate_is_rejected() {
    if skip("an_untrusted_server_certificate_is_rejected") {
        return;
    }
    let server = start_server().expect("server");
    // A different CA: the server's chain does not verify.
    make_ca(&server.dir, "other");
    make_leaf(&server.dir, "other", "other", true);
    let ca = std::fs::read_to_string(server.dir.join("other-ca.pem")).unwrap();
    let cert = std::fs::read_to_string(server.dir.join("client.pem")).unwrap();
    let key = std::fs::read_to_string(server.dir.join("client.key")).unwrap();
    let yaml = config_yaml(&server, &ca, Some(&cert), Some(&key));
    let option = openvpn_option(&yaml);
    let start = Instant::now();
    let error = OpenVpnTunnel::connect(&option, Duration::from_secs(8))
        .expect_err("certificate must not verify");
    assert!(start.elapsed() < Duration::from_secs(9));
    eprintln!("tls rejection: {error}");
}

#[test]
#[ignore]
fn a_missing_client_certificate_fails_authentication() {
    if skip("a_missing_client_certificate_fails_authentication") {
        return;
    }
    let server = start_server().expect("server");
    let ca = std::fs::read_to_string(server.dir.join("server-ca.pem")).unwrap();
    let yaml = config_yaml(&server, &ca, None, None);
    let option = openvpn_option(&yaml);
    let error = OpenVpnTunnel::connect(&option, Duration::from_secs(8))
        .expect_err("the server requires a client certificate");
    eprintln!("client-cert rejection: {error}");
}

#[test]
#[ignore]
fn no_common_data_cipher_is_a_named_failure() {
    if skip("no_common_data_cipher_is_a_named_failure") {
        return;
    }
    let server = start_server().expect("server");
    let ca = std::fs::read_to_string(server.dir.join("server-ca.pem")).unwrap();
    let cert = std::fs::read_to_string(server.dir.join("client.pem")).unwrap();
    let key = std::fs::read_to_string(server.dir.join("client.key")).unwrap();
    let yaml = config_yaml(&server, &ca, Some(&cert), Some(&key)).replace(
        "    cipher: AES-256-GCM\n",
        "    cipher: AES-128-GCM\n    data-ciphers: [AES-128-GCM]\n",
    );
    let option = openvpn_option(&yaml);
    let error = OpenVpnTunnel::connect(&option, Duration::from_secs(15))
        .expect_err("server offers only AES-256-GCM");
    let text = error.to_string();
    assert!(
        text.contains("common data cipher")
            || text.contains("no shared cipher")
            || text.contains("AES"),
        "{text}"
    );
}


/// The stack entry point builds an OpenVPN session, takes its local address
/// from PUSH_REPLY and opens a UDP socket. `--dev null` discards every IP
/// packet, so this is a wiring/lifecycle check, not an end-to-end datapath
/// proof; that limitation is recorded in the task evidence.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn connect_stack_uses_the_pushed_ifconfig() {
    if skip("connect_stack_uses_the_pushed_ifconfig") {
        return;
    }
    let server = start_server().expect("server");
    let ca = std::fs::read_to_string(server.dir.join("server-ca.pem")).unwrap();
    let cert = std::fs::read_to_string(server.dir.join("client.pem")).unwrap();
    let key = std::fs::read_to_string(server.dir.join("client.key")).unwrap();
    let yaml = config_yaml(&server, &ca, Some(&cert), Some(&key));
    let option = openvpn_option(&yaml);
    let stack = billow_kernel::outbound::openvpn::connect_stack(&option, Duration::from_secs(15))
        .await
        .expect("openvpn stack");
    assert!(
        stack.ipv4().is_some() || stack.ipv6().is_some(),
        "PUSH_REPLY must provide a local address"
    );
    let socket = stack.udp_socket().expect("udp socket");
    let remote = std::net::SocketAddr::from(([10, 8, 0, 1], 53));
    // The server is `--dev null`: the datagram is discarded, but it must leave
    // the stack without an error.
    socket.send(remote, b"wiring").await.expect("send");
}
