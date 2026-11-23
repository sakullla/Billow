//! SSH outbound (`adapter/outbound/ssh.go`).
//!
//! One SSH client connection is opened per dial, authenticated with the
//! configured password and/or inline private key, and one `direct-tcpip`
//! channel carries the target byte stream. Host keys are accepted without
//! verification unless `host-key` pins them, which is Mihomo's
//! `InsecureIgnoreHostKey` default; `host-key-algorithms` narrows the
//! negotiation the same way `ClientConfig.HostKeyAlgorithms` does.
//!
//! The pinned outbound keeps one client per proxy and multiplexes channels on
//! it. This kernel keeps the same wire protocol but opens a connection per
//! dial, so a server sees more SSH sessions; the observable `direct-tcpip`
//! behaviour (target, payload, auth failure) is identical. The server socket
//! comes from the shared outbound dialer so the `BasicOption` knobs are not
//! silently bypassed by `russh`'s own `TcpStream::connect`.

use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use russh::client;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{connect_tcp, handshake, BoxStream, DialError, Dialed, Target};
use crate::proxies::SshOutbound;

/// Client handler: accepts any host key when the configuration pins none,
/// otherwise requires a byte-identical `key_data` match with one of the
/// authorized keys.
struct Handler {
    host_keys: Vec<PublicKey>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        if self.host_keys.is_empty() {
            return Ok(true);
        }
        Ok(self
            .host_keys
            .iter()
            .any(|expected| expected.key_data() == server_public_key.key_data()))
    }
}

/// A `direct-tcpip` channel kept alive by its owning client handle.
struct SshStream {
    inner: russh::ChannelStream<client::Msg>,
    _session: client::Handle<Handler>,
}

impl AsyncRead for SshStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn error(message: impl std::fmt::Display) -> DialError {
    handshake("ssh", io::Error::other(message.to_string()))
}

fn load_private_key(option: &SshOutbound) -> Result<PrivateKey, DialError> {
    let pem = option
        .private_key
        .as_ref()
        .expect("caller checked private_key");
    let parsed = PrivateKey::from_openssh(pem.expose().as_bytes())
        .map_err(|e| error(format!("private key: {e}")))?;
    if parsed.is_encrypted() {
        let passphrase = option
            .private_key_passphrase
            .as_ref()
            .ok_or_else(|| error("private key is encrypted but no passphrase is configured"))?;
        parsed
            .decrypt(passphrase.expose().as_bytes())
            .map_err(|e| error(format!("private key passphrase: {e}")))
    } else {
        Ok(parsed)
    }
}

pub async fn dial(option: &SshOutbound, target: &Target) -> Result<Dialed, DialError> {
    // The connection to the SSH server is opened by the shared dialer (not by
    // `russh::client::connect`, which builds its own `TcpStream`), so the
    // per-outbound BasicOption knobs (`tfo`, `mptcp`, `interface-name`,
    // `routing-mark`) and `ip-version` apply to the socket, exactly like every
    // other outbound. `connect_stream` consumes that stream for the handshake.
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server: SocketAddr = tcp
        .peer_addr()
        .map_err(|e| error(format!("peer address: {e}")))?;
    let mut preferred = russh::Preferred::default();
    if !option.host_key_algorithms.is_empty() {
        use std::str::FromStr;
        let mut algorithms = Vec::with_capacity(option.host_key_algorithms.len());
        for name in &option.host_key_algorithms {
            algorithms.push(
                russh::keys::Algorithm::from_str(name)
                    .map_err(|e| error(format!("host-key-algorithms '{name}': {e}")))?,
            );
        }
        preferred.key = Cow::Owned(algorithms);
    }
    let config = client::Config {
        client_id: russh::SshId::Standard("SSH-2.0-OpenSSH_8.9".to_string()),
        preferred,
        nodelay: true,
        ..client::Config::default()
    };
    let mut host_keys = Vec::with_capacity(option.host_key.len());
    for line in &option.host_key {
        host_keys.push(
            PublicKey::from_openssh(line)
                .map_err(|e| error(format!("host-key '{line}': {e}")))?,
        );
    }
    let handler = Handler { host_keys };
    let mut session = client::connect_stream(Arc::new(config), tcp, handler)
        .await
        .map_err(|e| error(format!("connect: {e}")))?;

    let mut authenticated = false;
    if option.private_key.is_some() {
        let key = Arc::new(load_private_key(option)?);
        let hash = session
            .best_supported_rsa_hash()
            .await
            .map_err(|e| error(format!("rsa hash negotiation: {e}")))?
            .flatten();
        let result = session
            .authenticate_publickey(
                option.username.clone(),
                PrivateKeyWithHashAlg::new(key, hash),
            )
            .await
            .map_err(|e| error(format!("publickey authentication: {e}")))?;
        if !result.success() {
            return Err(error("publickey authentication was rejected by the server"));
        }
        authenticated = true;
    }
    if !authenticated {
        if let Some(password) = &option.password {
            let result = session
                .authenticate_password(option.username.clone(), password.expose().to_string())
                .await
                .map_err(|e| error(format!("password authentication: {e}")))?;
            if !result.success() {
                return Err(error("password authentication was rejected by the server"));
            }
        } else {
            let result = session
                .authenticate_none(option.username.clone())
                .await
                .map_err(|e| error(format!("none authentication: {e}")))?;
            if !result.success() {
                return Err(error("no authentication method was accepted"));
            }
        }
    }

    let channel = session
        .channel_open_direct_tcpip(
            target.host.clone(),
            u32::from(target.port),
            "127.0.0.1",
            0,
        )
        .await
        .map_err(|e| error(format!("direct-tcpip {}: {e}", target.authority())))?;
    let stream: BoxStream = Box::new(SshStream {
        inner: channel.into_stream(),
        _session: session,
    });
    Ok(Dialed { stream, server })
}
