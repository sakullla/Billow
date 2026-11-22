//! Routing for the packet tunnel (feature `ios-vpn`).
//!
//! The iOS Packet Tunnel is a second entry point into the same engine the
//! mixed listener uses: a device flow is turned into a [`crate::rules::Target`]
//! and evaluated against the *current generation's* rules, proxy groups and
//! DNS, then dialled through the selected outbound. The decision code mirrors
//! `engine::serve_request`/`engine::serve_udp_associate` (rule -> group ->
//! direct/proxy) so a configuration behaves the same whether the connection
//! arrives through the listener or through the tunnel.
//!
//! Everything here is `pub(crate)`: only [`crate::tunnel::Tunnel`] uses it.

use std::net::IpAddr;

use crate::config::{Action, InType, NetworkKind};
use crate::engine::{
    chain_for, direct_stream, pre_handle_destination, rule_decision, rule_payload_text,
    rule_type_name, SessionContext,
};
use crate::groups::Selected;
use crate::outbound::{self, BoxStream, DialError};
use crate::rules::{RuleMatch, Target};

/// Where a device flow goes.
pub(crate) enum Route {
    /// Dial locally (pinned `DIRECT`).
    Direct,
    /// Dial through the leaf outbound of the rule; `path` is the group chain
    /// outward (`chain_for` turns it into a `dialer-proxy` chain).
    Proxy {
        proxy: std::sync::Arc<crate::proxies::Proxy>,
        path: Vec<String>,
    },
}

/// One routed TCP flow, ready to relay bytes.
pub(crate) struct RoutedTcp {
    pub stream: BoxStream,
    pub rule: String,
    pub rule_payload: String,
    pub rule_kind: String,
    /// `DIRECT` or `proxy=<name> type=<type> server=<addr> chain=<a->b>`.
    pub outbound: String,
    /// Pinned `chains` for `/connections`.
    pub chains: Vec<String>,
    pub host: String,
    pub ip: Option<IpAddr>,
}

/// A refused flow with the reason the extension logs and reports.
pub(crate) struct RouteFailure {
    pub reason: String,
}

/// The destination a device flow asks for: the packet address, mapped back
/// through fake-ip/hosts exactly like an inbound request (`preHandleMetadata`).
pub(crate) async fn destination(
    session: &SessionContext,
    addr: IpAddr,
    port: u16,
    network: NetworkKind,
    source: std::net::SocketAddr,
) -> Result<Target, String> {
    let (host, ip) = pre_handle_destination(session, "", Some(addr)).await?;
    Ok(Target::new(&host, ip)
        .with_port(port)
        .with_network(network)
        .with_source(source.ip(), source.port())
        .with_inbound(session.listen_port(), InType::Tun))
}

/// Rule decision plus group resolution for `target`.
pub(crate) async fn decide(
    session: &SessionContext,
    target: &mut Target,
    udp: bool,
) -> Result<(Route, RuleMatch), RouteFailure> {
    let decision = rule_decision(session, target).await;
    let rule = decision.to_string();
    match decision.action {
        Action::Reject | Action::RejectDrop => {
            return Err(RouteFailure {
                reason: format!("{rule} (rule)"),
            })
        }
        _ => {}
    }
    let selected = match session
        .runtime
        .groups
        .resolve_action(decision.action, target, true)
    {
        Ok(selected) => selected,
        Err(error) => {
            return Err(RouteFailure {
                reason: format!("group resolution for {rule}: {error}"),
            })
        }
    };
    let route = match selected {
        Selected::Direct => Route::Direct,
        Selected::Reject => {
            return Err(RouteFailure {
                reason: format!("{rule} (group member: REJECT)"),
            })
        }
        Selected::RejectDrop => {
            return Err(RouteFailure {
                reason: format!("{rule} (group member: REJECT-DROP)"),
            })
        }
        Selected::Proxy { proxy, path } => {
            if udp && session.runtime.groups.path_disables_udp(&path) {
                return Err(RouteFailure {
                    reason: format!("{rule} (group {} sets disable-udp)", path.join("->")),
                });
            }
            Route::Proxy { proxy, path }
        }
    };
    Ok((route, decision))
}

/// Dial one TCP flow through the decided route (same selection the mixed
/// listener performs; only the reply/relay part differs).
pub(crate) async fn dial_tcp(
    session: &SessionContext,
    route: Route,
    decision: &RuleMatch,
    target: &Target,
    host: String,
    ip: Option<IpAddr>,
    timeout: std::time::Duration,
) -> Result<RoutedTcp, RouteFailure> {
    let config = session.runtime.config.clone();
    let rule = decision.to_string();
    let rule_kind = rule_type_name(&decision.rule.matcher);
    let rule_payload = rule_payload_text(&decision.rule.matcher);
    let port = target.port;
    let (stream, outbound, chains): (BoxStream, String, Vec<String>) = match route {
        Route::Direct => {
            let stream = match tokio::time::timeout(
                timeout,
                direct_stream(session, &host, ip, port),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    return Err(RouteFailure {
                        reason: format!("DIRECT {host}:{port}: {error}"),
                    })
                }
                Err(_) => {
                    return Err(RouteFailure {
                        reason: format!("DIRECT {host}:{port}: timed out after {timeout:?}"),
                    })
                }
            };
            let _ = stream.set_nodelay(true);
            let peer = stream
                .peer_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "?".to_string());
            (
                Box::new(stream) as BoxStream,
                format!("DIRECT {peer}"),
                vec!["DIRECT".to_string()],
            )
        }
        Route::Proxy { proxy, path } => {
            let hops = chain_for(&config, &proxy);
            let dial_host = if host.is_empty() {
                ip.map(|ip| ip.to_string()).unwrap_or_default()
            } else {
                host.clone()
            };
            let dial_target = outbound::Target {
                host: dial_host,
                port,
            };
            let dial = async {
                match &session.runtime.dns {
                    Some(dns) => {
                        outbound::with_proxy_dns(
                            dns.clone(),
                            outbound::dial_chain(
                                &hops,
                                &dial_target,
                                timeout,
                                &session.runtime.tls,
                            ),
                        )
                        .await
                    }
                    None => {
                        outbound::dial_chain(&hops, &dial_target, timeout, &session.runtime.tls)
                            .await
                    }
                }
            };
            match tokio::time::timeout(timeout, dial).await {
                Err(_) => {
                    session.runtime.groups.note_dial_failure(&path, "timeout");
                    return Err(RouteFailure {
                        reason: format!("{}: dial timed out after {timeout:?}", proxy.name),
                    });
                }
                Ok(Err(error)) => {
                    session
                        .runtime
                        .groups
                        .note_dial_failure(&path, &error.to_string());
                    let detail = match &error {
                        DialError::Timeout(limit) => format!("timed out after {limit:?}"),
                        other => other.to_string(),
                    };
                    return Err(RouteFailure {
                        reason: format!("{}: {detail}", proxy.name),
                    });
                }
                Ok(Ok(dialed)) => {
                    session.runtime.groups.note_dial_success(&path);
                    let label = hops
                        .iter()
                        .map(|hop| hop.name.as_str())
                        .collect::<Vec<_>>()
                        .join("->");
                    let mut names = vec![proxy.name.clone()];
                    names.extend(path.iter().rev().cloned());
                    (
                        dialed.stream,
                        format!(
                            "proxy={} type={} server={} chain={label}",
                            proxy.name,
                            proxy.type_name(),
                            dialed.server
                        ),
                        names,
                    )
                }
            }
        }
    };
    Ok(RoutedTcp {
        stream,
        rule,
        rule_payload,
        rule_kind,
        outbound,
        chains,
        host,
        ip,
    })
}
