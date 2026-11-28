//! Bounded HTTP Host and TLS ClientHello inspection for transparent TCP flows.

use std::net::IpAddr;
use std::ops::RangeInclusive;

use serde_yaml::{Mapping, Value};

use crate::config::ConfigError;
use crate::config::ipnet_like::IpNet;
use crate::geodata::DomainPattern;

pub(crate) const MAX_PREFIX: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct Sniffer {
    pub enabled: bool,
    pure_ip: bool,
    dns_mapping: bool,
    http: Option<Protocol>,
    tls: Option<Protocol>,
    force: Vec<String>,
    skip: Vec<String>,
    skip_src: Vec<IpNet>,
    skip_dst: Vec<IpNet>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Protocol {
    ports: Vec<RangeInclusive<u16>>,
    rewrite: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Inspection {
    NeedMore,
    NoHost,
    Host(String, bool),
}

impl Sniffer {
    pub fn parse(value: &Value, warnings: &mut Vec<String>) -> Result<Self, ConfigError> {
        let error = |message: &str| ConfigError::InvalidValue(format!("sniffer: {message}"));
        if value.is_null() { return Ok(Self::default()); }
        let map = value.as_mapping().ok_or_else(|| error("expected a mapping"))?;
        let enabled = flag(map, "enable")?.unwrap_or(false);
        if !enabled { return Ok(Self::default()); }
        let rewrite = flag(map, "override-destination")?.unwrap_or(false);
        let mut sniffer = Self {
            enabled,
            pure_ip: flag(map, "parse-pure-ip")?.unwrap_or(false),
            dns_mapping: flag(map, "force-dns-mapping")?.unwrap_or(false),
            force: strings(map.get("force-domain"))?,
            skip: strings(map.get("skip-domain"))?,
            skip_src: prefixes(map.get("skip-src-address"))?,
            skip_dst: prefixes(map.get("skip-dst-address"))?,
            ..Self::default()
        };
        if sniffer.force.iter().chain(&sniffer.skip).any(|name| name.starts_with("geosite:") || name.starts_with("rule-set:")) {
            return Err(ConfigError::Unsupported("sniffer domain filters cannot yet reference GEOSITE or rule providers".to_string()));
        }
        if let Some(options) = map.get("sniff").filter(|options| !options.is_null()) {
            let protocols = options.as_mapping().ok_or_else(|| error("sniff must be a mapping"))?;
            for (name, value) in protocols {
                let name = name.as_str().ok_or_else(|| error("sniff protocol must be a string"))?;
                let options = value.as_mapping();
                if !value.is_null() && options.is_none() {
                    return Err(error("sniff protocol settings must be a mapping"));
                }
                let protocol = Protocol {
                    ports: ports(options.and_then(|map| map.get("ports")))?,
                    rewrite: options.map(|map| flag(map, "override-destination")).transpose()?.flatten().unwrap_or(rewrite),
                };
                sniffer.set_protocol(name, protocol, warnings)?;
            }
        } else {
            let ports = ports(map.get("port-whitelist"))?;
            for name in strings(map.get("sniffing"))? {
                sniffer.set_protocol(&name, Protocol { ports: ports.clone(), rewrite }, warnings)?;
            }
        }
        Ok(sniffer)
    }

    fn set_protocol(&mut self, name: &str, protocol: Protocol, warnings: &mut Vec<String>) -> Result<(), ConfigError> {
        match name.to_ascii_uppercase().as_str() {
            "HTTP" => self.http = Some(protocol),
            "TLS" => self.tls = Some(protocol),
            "QUIC" => warnings.push("sniffer: QUIC inspection is unavailable in this kernel".to_string()),
            _ => return Err(ConfigError::InvalidValue(format!("unknown sniffer protocol '{name}'"))),
        }
        Ok(())
    }

    pub fn wants_tcp(&self, host: &str, source: IpAddr, destination: IpAddr, port: u16) -> bool {
        if !self.enabled || (!matches_port(&self.http, port) && !matches_port(&self.tls, port)) ||
            self.skip_src.iter().any(|net| net.contains(source)) ||
            self.skip_dst.iter().any(|net| net.contains(destination)) {
            return false;
        }
        let forced = domain_matches(&self.force, host);
        let literal = host.is_empty() || host.parse::<IpAddr>().is_ok();
        forced || (literal && self.pure_ip) || (!literal && self.dns_mapping)
    }

    pub fn inspect_tcp(&self, data: &[u8], port: u16) -> Inspection {
        let Some(first) = data.first() else { return Inspection::NeedMore };
        let (extract, options) = if *first == 22 {
            (inspect_tls as fn(&[u8]) -> Inspection, self.tls.as_ref())
        } else if first.is_ascii_uppercase() {
            (inspect_http as fn(&[u8]) -> Inspection, self.http.as_ref())
        } else {
            return Inspection::NoHost;
        };
        let Some(options) = options.filter(|entry| entry.ports.is_empty() || entry.ports.iter().any(|range| range.contains(&port))) else { return Inspection::NoHost };
        match extract(data) {
            Inspection::Host(host, _) if !domain_matches(&self.skip, &host) => Inspection::Host(host, options.rewrite),
            Inspection::Host(_, _) => Inspection::NoHost,
            Inspection::NeedMore if data.len() >= MAX_PREFIX => Inspection::NoHost,
            other => other,
        }
    }
}

fn flag(map: &Mapping, name: &str) -> Result<Option<bool>, ConfigError> {
    map.get(name).map(|value| value.as_bool().ok_or_else(|| ConfigError::InvalidValue(format!("sniffer.{name} must be a boolean")))).transpose()
}

fn strings(value: Option<&Value>) -> Result<Vec<String>, ConfigError> {
    let Some(value) = value.filter(|value| !value.is_null()) else { return Ok(Vec::new()); };
    let items = value.as_sequence().ok_or_else(|| ConfigError::InvalidValue("expected a sniffer list".into()))?;
    items.iter().map(|value| {
        value.as_str().map(str::to_string)
            .or_else(|| value.as_u64().map(|value| value.to_string()))
            .ok_or_else(|| ConfigError::InvalidValue("invalid sniffer list entry".into()))
    }).collect()
}

fn prefixes(value: Option<&Value>) -> Result<Vec<IpNet>, ConfigError> {
    strings(value)?.into_iter().map(|value| value.parse().map_err(|error| {
        ConfigError::InvalidValue(format!("sniffer CIDR '{value}': {error}"))
    })).collect()
}

fn ports(value: Option<&Value>) -> Result<Vec<RangeInclusive<u16>>, ConfigError> {
    strings(value)?.iter().flat_map(|value| value.split(',')).map(|value| {
        let (start, end) = value.trim().split_once('-').unwrap_or((value, value));
        let (start, end) = (start.trim().parse::<u16>(), end.trim().parse::<u16>());
        match (start, end) {
            (Ok(start), Ok(end)) if start <= end => Ok(start..=end),
            _ => Err(ConfigError::InvalidValue(format!("sniffer port range '{value}' is invalid"))),
        }
    }).collect()
}

fn matches_port(protocol: &Option<Protocol>, port: u16) -> bool {
    protocol.as_ref().is_some_and(|entry| entry.ports.is_empty() || entry.ports.iter().any(|range| range.contains(&port)))
}

fn domain_matches(list: &[String], host: &str) -> bool {
    !host.is_empty() && list.iter().any(|name| DomainPattern::parse(name).matches(host))
}

fn validated_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    (!host.is_empty() && host.len() <= 253 && host.parse::<IpAddr>().is_err() &&
        host.split('.').all(|label| !label.is_empty() && label.len() <= 63 && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')))
        .then(|| host.to_ascii_lowercase())
}

fn inspect_http(data: &[u8]) -> Inspection {
    let Some(first_line) = data.iter().position(|byte| *byte == b'\n') else { return Inspection::NeedMore };
    let request = &data[..first_line];
    if !request.windows(6).any(|word| word == b" HTTP/") {
        return Inspection::NoHost;
    }
    let Some(end) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") else { return Inspection::NeedMore };
    let Ok(headers) = std::str::from_utf8(&data[first_line + 1..end + 2]) else { return Inspection::NoHost };
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                let host = value.trim().split(':').next().unwrap_or_default();
                return validated_host(host).map_or(Inspection::NoHost, |host| Inspection::Host(host, false));
            }
        }
    }
    Inspection::NoHost
}

fn take<'a>(data: &mut &'a [u8], length: usize) -> Option<&'a [u8]> {
    let (prefix, rest) = data.split_at_checked(length)?;
    *data = rest;
    Some(prefix)
}

fn read_length(data: &mut &[u8], bytes: usize) -> Option<usize> {
    Some(take(data, bytes)?.iter().fold(0, |value, byte| value * 256 + usize::from(*byte)))
}

fn inspect_tls(data: &[u8]) -> Inspection {
    let mut input = data;
    let mut handshake = Vec::new();
    loop {
        let Some(record) = take(&mut input, 5) else { return Inspection::NeedMore };
        if record[0] != 22 || record[1] != 3 { return Inspection::NoHost; }
        let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
        let Some(bytes) = take(&mut input, length) else { return Inspection::NeedMore };
        handshake.extend_from_slice(bytes);
        if handshake.first().is_some_and(|kind| *kind != 1) { return Inspection::NoHost; }
        if handshake.len() < 4 { continue; }
        let length = handshake[1..4].iter().fold(0, |n, b| n * 256 + usize::from(*b));
        if length > MAX_PREFIX - 4 { return Inspection::NoHost; }
        if handshake.len() >= length + 4 {
            return client_hello_host(&handshake[4..4+length]).map_or(Inspection::NoHost, |host| Inspection::Host(host, false));
        }
    }
}

fn client_hello_host(mut body: &[u8]) -> Option<String> {
    take(&mut body, 34)?;
    for size in [1, 2, 1] {
        let length = read_length(&mut body, size)?;
        take(&mut body, length)?;
    }
    let length = read_length(&mut body, 2)?;
    let mut extensions = take(&mut body, length)?;
    while !extensions.is_empty() {
        let kind = read_length(&mut extensions, 2)?;
        let length = read_length(&mut extensions, 2)?;
        let mut extension = take(&mut extensions, length)?;
        if kind != 0 { continue; }
        let length = read_length(&mut extension, 2)?;
        let mut names = take(&mut extension, length)?;
        while !names.is_empty() {
            let kind = read_length(&mut names, 1)?;
            let length = read_length(&mut names, 2)?;
            let name = take(&mut names, length)?;
            if kind == 0 { return validated_host(std::str::from_utf8(name).ok()?); }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_http_host_without_consuming_data() {
        assert_eq!(inspect_http(b"GET / HTTP/1.1\r\nHo"), Inspection::NeedMore);
        assert_eq!(inspect_http(b"GET / HTTP/1.1\r\nHost: EXAMPLE.test:80\r\n\r\nbody"), Inspection::Host("example.test".into(), false));
    }

    #[test]
    fn reads_sni_from_a_fragmented_client_hello() {
        let name = b"example.test";
        let mut body = vec![0; 34];
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        body.extend((name.len() as u16 + 9).to_be_bytes());
        body.extend([0, 0]);
        body.extend((name.len() as u16 + 5).to_be_bytes());
        body.extend((name.len() as u16 + 3).to_be_bytes());
        body.push(0);
        body.extend((name.len() as u16).to_be_bytes());
        body.extend(name);
        let mut handshake = vec![1, 0];
        handshake.extend((body.len() as u16).to_be_bytes());
        handshake.extend(body);
        let mut wire = Vec::new();
        for record in [&handshake[..24], &handshake[24..]] {
            wire.extend([22, 3, 3]);
            wire.extend((record.len() as u16).to_be_bytes());
            wire.extend(record);
        }
        assert_eq!(inspect_tls(&wire[..12]), Inspection::NeedMore);
        assert_eq!(inspect_tls(&wire), Inspection::Host("example.test".into(), false));
    }
}
