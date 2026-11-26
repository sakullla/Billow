//! Desktop CLI acceptance for `--check`/`--tun` (feature `desktop-tun`).
//!
//! `--check` must validate a `tun`-enabled configuration without creating a
//! device or asking for TUN authorization. That is the property this test
//! exercises by running the real binary; a successful `--tun` launch is
//! covered by the ignored, privilege-dependent test in the library suite.

#![cfg(feature = "desktop-tun")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

fn config_dir(tag: &str, yaml: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "billow-desktop-cli-{}-{tag}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("config.yaml"), yaml).expect("config.yaml");
    dir
}

#[test]
fn check_validates_a_tun_configuration_without_creating_a_device() {
    let yaml = format!(
        "mixed-port: {}\ntun:\n  enable: true\n  stack: gvisor\n  mtu: 1400\n  auto-route: true\n  auto-detect-interface: true\n  dns-hijack: [any:53]\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let dir = config_dir("check", &yaml);
    let config = dir.join("config.yaml");
    for extra in [&[] as &[&str], &["--tun"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
            .arg(&config)
            .arg("--check")
            .arg("--port")
            .arg("0")
            .args(extra)
            .output()
            .expect("run the CLI");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{}: stdout={stdout} stderr={stderr}",
            if extra.is_empty() { "--check" } else { "--tun --check" }
        );
        assert!(stdout.contains("configuration accepted"), "{stdout}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rejected_tun_shape_exits_non_zero_with_its_name() {
    let yaml = format!(
        "mixed-port: {}\ntun: {{enable: true, stack: system}}\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let dir = config_dir("reject", &yaml);
    let output = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(dir.join("config.yaml"))
        .arg("--check")
        .output()
        .expect("run the CLI");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("tun.stack 'system'"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
