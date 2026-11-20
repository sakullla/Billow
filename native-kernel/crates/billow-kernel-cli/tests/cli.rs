//! Drives the real `billow-kernel` process: start, forward via HTTP CONNECT and
//! SOCKS5, reject, stop with SIGINT and start again on the same port.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Loopback echo server in a background thread; returns its port.
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

struct KernelProcess {
    child: Child,
    config: PathBuf,
}

impl KernelProcess {
    fn start(rules: &[&str], port: u16) -> KernelProcess {
        let dir = std::env::temp_dir().join(format!("billow-cli-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.yaml");
        let body = rules
            .iter()
            .map(|r| format!("  - '{r}'\n"))
            .collect::<String>();
        std::fs::write(
            &config,
            format!("mixed-port: {port}\nlog-level: info\nrules:\n{body}"),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn billow-kernel");
        wait_for_port(port);
        KernelProcess { child, config }
    }

    fn sigint(&mut self) -> std::process::Output {
        #[cfg(unix)]
        {
            unsafe {
                extern "C" {
                    fn kill(pid: i32, sig: i32) -> i32;
                }
                assert_eq!(kill(self.child.id() as i32, 2), 0, "send SIGINT");
            }
            wait_with_timeout(&mut self.child, Duration::from_secs(10))
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
            wait_with_timeout(&mut self.child, Duration::from_secs(10))
        }
    }
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> std::process::Output {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut out) = child.stdout.take() {
                let _ = out.read_to_string(&mut stdout);
            }
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_string(&mut stderr);
            }
            return std::process::Output {
                status,
                stdout: stdout.into_bytes(),
                stderr: stderr.into_bytes(),
            };
        }
        assert!(
            Instant::now() < deadline,
            "kernel did not exit within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("kernel never listened on {port}");
}

fn http_connect(proxy: SocketAddr, authority: &str) -> std::io::Result<(TcpStream, String)> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.write_all(
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
    )?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let status = text.lines().next().unwrap_or_default().to_string();
    Ok((stream, status))
}

fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection)?;
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply)?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!(
            "socks reply 0x{:02x}",
            reply[1]
        )));
    }
    let mut rest = [0u8; 6];
    stream.read_exact(&mut rest)?;
    Ok(stream)
}

fn roundtrip(stream: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
    stream.write_all(payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).unwrap();
    got
}

fn identity_line(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find(|line| line.starts_with("instance="))
        .unwrap_or_default()
        .to_string()
}

#[test]
fn process_forwards_both_protocols_rejects_and_restarts() {
    let echo_port = spawn_echo();
    let port = free_port();
    let rules = ["DOMAIN-SUFFIX,blocked.test,REJECT", "MATCH,DIRECT"];

    for round in 0..2 {
        let mut kernel = KernelProcess::start(&rules, port);
        let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // HTTP CONNECT to the echo endpoint.
        let (mut tunnel, status) = http_connect(proxy, &format!("127.0.0.1:{echo_port}")).unwrap();
        assert_eq!(
            status, "HTTP/1.1 200 Connection Established",
            "round {round}"
        );
        assert_eq!(roundtrip(&mut tunnel, b"http-payload"), b"http-payload");
        drop(tunnel);

        // SOCKS5 to the same endpoint on the same port.
        let mut tunnel = socks5_connect(proxy, "127.0.0.1", echo_port).unwrap();
        assert_eq!(roundtrip(&mut tunnel, b"socks-payload"), b"socks-payload");
        drop(tunnel);

        // A REJECT rule blocks the request.
        let (_tunnel, status) = http_connect(proxy, &format!("blocked.test:{echo_port}")).unwrap();
        assert_eq!(status, "HTTP/1.1 403 Forbidden");

        let output = kernel.sigint();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(
            output.status.success(),
            "round {round} exit: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let identity = identity_line(&output.stdout);
        assert!(
            identity.contains(&format!("listen=127.0.0.1:{port}")),
            "{identity}"
        );
        assert!(identity.contains("version="), "{identity}");
        assert!(identity.contains("pid="), "{identity}");
        assert!(stdout.contains("completed="), "{stdout}");
        // The port is free again, so the next round can bind it.
        assert!(
            TcpListener::bind(("127.0.0.1", port)).is_ok(),
            "round {round}: port released after SIGINT"
        );
        let _ = std::fs::remove_file(&kernel.config);
    }
}

#[test]
fn process_rejects_unimplemented_config_and_exits_non_zero() {
    let dir = std::env::temp_dir().join(format!("billow-cli-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("bad.yaml");
    std::fs::write(
        &config,
        "mixed-port: 1\ndns:\n  enable: true\nrules:\n  - 'MATCH,DIRECT'\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[unsupported]"), "{stderr}");
    assert!(stderr.contains("'dns'"), "{stderr}");

    std::fs::write(&config, "mixed-port: 1\nrules:\n  - 'GEOIP,CN,DIRECT'\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rule type 'GEOIP'"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
