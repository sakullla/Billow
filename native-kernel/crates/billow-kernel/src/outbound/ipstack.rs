//! Minimal IPv4/IPv6 + UDP codec for the MASQUE CONNECT-IP tunnel
//! (RFC 9484 §4: IP packets travel as HTTP Datagrams, whole and unmodified).
//!
//! This is the whole "IP stack" the kernel has: it is enough to carry the
//! SOCKS5 UDP association over a tunnel that only speaks IP, and deliberately
//! not more.
//!
//! * IPv4: 20-byte headers only (no options), header checksum verified when
//!   parsing and computed when building; DF is set on built packets, and a
//!   fragmented packet is refused instead of being reassembled.
//! * IPv6: 40-byte headers, no extension headers (a non-UDP next header is
//!   refused by name instead of being followed).
//! * UDP: length checked against the IP payload, checksum verified when the
//!   peer sends one (mandatory for IPv6) and always computed on built packets.
//! * TCP and every other IP protocol are reported as unsupported: terminating
//!   TCP needs a full TCP state machine, which this kernel does not have (the
//!   pinned adapter uses mipstack/gVisor for that). ICMP has no socket surface
//!   here either; it is reported and dropped.
//!
//! The bounds are the protocol's: a UDP payload is at most 65,507 bytes over
//! IPv4 and 65,527 over IPv6; the tunnel MTU is applied by the caller
//! (`masque_ip`) so a datagram is refused rather than fragmented.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Smallest tunnel MTU that can carry an IPv4 packet (RFC 791 total length).
pub const MIN_MTU: usize = 68;

/// Pinned `masque.mtu` default (`adapter/outbound/masque.go`: `if mtu == 0 {
/// mtu = 1280 }`).
pub const DEFAULT_MTU: u16 = 1280;

/// IPv4 + UDP overhead (20 + 8 bytes).
pub const IPV4_UDP_OVERHEAD: usize = 28;

/// IPv6 + UDP overhead (40 + 8 bytes).
pub const IPV6_UDP_OVERHEAD: usize = 48;

/// IPv4 + TCP overhead (20 + 20 bytes).
pub const IPV4_TCP_OVERHEAD: usize = 40;

/// IPv6 + TCP overhead (40 + 20 bytes).
pub const IPV6_TCP_OVERHEAD: usize = 60;

/// IP protocol number of TCP (RFC 793).
pub const IPPROTO_TCP: u8 = 6;
/// IP protocol number of UDP.
pub const IPPROTO_UDP: u8 = 17;

/// One local address of the tunnel, in the shape of the `ip`/`ipv6` options
/// (an address without a prefix length is a host prefix, as in the pinned
/// adapter's `netip.ParsePrefix` after appending `/32` or `/128`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub bits: u8,
}

impl IpPrefix {
    /// Parse `1.2.3.4`, `1.2.3.4/24`, `fd00::2` or `fd00::2/128`. Host bits
    /// below the prefix length are accepted and masked, matching
    /// `netip.ParsePrefix` (it keeps them; only the tunnel use needs the
    /// network form).
    pub fn parse(text: &str) -> Result<IpPrefix, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty address".to_string());
        }
        let (addr_text, bits_text) = match text.split_once('/') {
            Some((addr, bits)) => (addr, Some(bits)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text
            .parse()
            .map_err(|_| format!("'{addr_text}' is not an IP address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits_text {
            Some(bits) => bits
                .parse::<u8>()
                .map_err(|_| format!("'{bits}' is not a prefix length"))?,
            None => max,
        };
        if bits > max {
            return Err(format!(
                "prefix length {bits} exceeds the address width {max}"
            ));
        }
        Ok(IpPrefix { addr, bits })
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                let mask = v4_mask(self.bits);
                (u32::from(network) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                let mask = v6_mask(self.bits);
                (u128::from(network) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }

    /// The address in the network form of the prefix (`ip/len` masked). A host
    /// prefix (`/32`, `/128`) is the address itself.
    pub fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(addr) => IpAddr::V4(Ipv4Addr::from(u32::from(addr) & v4_mask(self.bits))),
            IpAddr::V6(addr) => IpAddr::V6(Ipv6Addr::from(u128::from(addr) & v6_mask(self.bits))),
        }
    }
}

fn v4_mask(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(bits.min(32)))
    }
}

fn v6_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(bits.min(128)))
    }
}

/// Why a packet could not be parsed or built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpError {
    /// The bytes are not a complete packet of a supported shape.
    Malformed(String),
    /// A well-formed packet this stack does not terminate (TCP, ICMP,
    /// extension headers, fragments).
    Unsupported(String),
}

impl fmt::Display for IpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpError::Malformed(what) => write!(f, "malformed IP packet: {what}"),
            IpError::Unsupported(what) => write!(f, "unsupported IP packet: {what}"),
        }
    }
}

impl std::error::Error for IpError {}

/// One parsed IP packet. `payload` borrows the input for the lifetime of the
/// parse, so a reader can hand a UDP payload out without a copy.
#[derive(Debug, Clone, Copy)]
pub struct IpPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub payload: &'a [u8],
}

/// Parse an IPv4 or IPv6 packet. Fragments and IPv6 extension headers are
/// refused by name: this stack does not reassemble or walk extension chains.
pub fn parse_ip_packet(bytes: &[u8]) -> Result<IpPacket<'_>, IpError> {
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) => parse_ipv4(bytes),
        Some(6) => parse_ipv6(bytes),
        Some(other) => Err(IpError::Malformed(format!("IP version {other}"))),
        None => Err(IpError::Malformed("empty packet".to_string())),
    }
}

fn parse_ipv4(bytes: &[u8]) -> Result<IpPacket<'_>, IpError> {
    if bytes.len() < 20 {
        return Err(IpError::Malformed(
            "IPv4 header shorter than 20 bytes".to_string(),
        ));
    }
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if header_len < 20 || header_len > bytes.len() {
        return Err(IpError::Malformed(format!(
            "IPv4 header length {header_len}"
        )));
    }
    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < header_len || total_len > bytes.len() {
        return Err(IpError::Malformed(format!(
            "IPv4 total length {total_len} (buffer {} bytes, header {header_len})",
            bytes.len()
        )));
    }
    // More-fragments bit or a non-zero fragment offset: no reassembly here.
    let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    if fragment & 0x3fff != 0 {
        return Err(IpError::Unsupported(
            "IPv4 fragment (reassembly is not implemented)".to_string(),
        ));
    }
    if internet_checksum(&bytes[..header_len]) != 0 {
        return Err(IpError::Malformed("IPv4 header checksum".to_string()));
    }
    let protocol = bytes[9];
    Ok(IpPacket {
        src: IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
        dst: IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
        protocol,
        payload: &bytes[header_len..total_len],
    })
}

fn parse_ipv6(bytes: &[u8]) -> Result<IpPacket<'_>, IpError> {
    if bytes.len() < 40 {
        return Err(IpError::Malformed(
            "IPv6 header shorter than 40 bytes".to_string(),
        ));
    }
    let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let end = 40 + payload_len;
    if end > bytes.len() {
        return Err(IpError::Malformed(format!(
            "IPv6 payload length {payload_len} exceeds the buffer ({} bytes)",
            bytes.len()
        )));
    }
    let next_header = bytes[6];
    if next_header != IPPROTO_UDP && next_header != IPPROTO_TCP && next_header != 58 {
        // 58 == ICMPv6 is kept so the caller can report it; every other value
        // (extension headers, ESP) is unsupported, but the message names what
        // was seen instead of guessing.
        return Err(IpError::Unsupported(format!(
            "IPv6 next header {next_header} (only UDP, TCP and ICMPv6 are recognised, extension headers are not walked)"
        )));
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&bytes[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&bytes[24..40]);
    Ok(IpPacket {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        protocol: next_header,
        payload: &bytes[40..end],
    })
}

/// One parsed UDP datagram: addresses, ports and payload.
#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parse a UDP datagram out of an IP packet (checksum included).
pub fn parse_udp<'a>(packet: &'a IpPacket<'a>) -> Result<UdpDatagram<'a>, IpError> {
    if packet.protocol == IPPROTO_TCP {
        return Err(IpError::Unsupported(
            "TCP is not terminated by this IP stack".to_string(),
        ));
    }
    if packet.protocol != IPPROTO_UDP {
        return Err(IpError::Unsupported(format!(
            "IP protocol {} (only UDP is terminated)",
            packet.protocol
        )));
    }
    let bytes = packet.payload;
    if bytes.len() < 8 {
        return Err(IpError::Malformed(
            "UDP header shorter than 8 bytes".to_string(),
        ));
    }
    let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if length < 8 || length > bytes.len() {
        return Err(IpError::Malformed(format!(
            "UDP length {length} (IP payload {} bytes)",
            bytes.len()
        )));
    }
    let checksum = u16::from_be_bytes([bytes[6], bytes[7]]);
    if checksum != 0 {
        if !udp_checksum_valid(packet.src, packet.dst, &bytes[..length]) {
            return Err(IpError::Malformed("UDP checksum".to_string()));
        }
    } else if packet.src.is_ipv6() {
        return Err(IpError::Malformed(
            "IPv6 UDP datagram without a checksum".to_string(),
        ));
    }
    Ok(UdpDatagram {
        src: packet.src,
        dst: packet.dst,
        src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        payload: &bytes[8..length],
    })
}

/// Build one IPv4 or IPv6 packet. The source and destination must be the same
/// family; `hop_limit` is the IPv4 TTL / IPv6 Hop Limit (the tunnel sets a
/// fixed value, nothing decrements it here because the packet is not routed).
/// The transport header (UDP/TCP) is `payload` and its checksum must already be
/// filled in: [`transport_checksum`] computes it over the pseudo-header.
pub fn build_packet(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    payload: &[u8],
    hop_limit: u8,
) -> Result<Vec<u8>, IpError> {
    build_packet_with(src, dst, protocol, payload.len(), hop_limit, |packet| {
        packet.extend_from_slice(payload);
    })
}

/// Allocate the whole packet once and let the caller write the transport bytes.
pub(super) fn build_packet_with(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    payload_len: usize,
    hop_limit: u8,
    write_payload: impl FnOnce(&mut Vec<u8>),
) -> Result<Vec<u8>, IpError> {
    let mut packet = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            if payload_len > usize::from(u16::MAX) - 20 {
                return Err(IpError::Malformed(format!(
                    "{} bytes exceeds the IPv4 maximum of {}",
                    payload_len,
                    usize::from(u16::MAX) - 20
                )));
            }
            let total = 20 + payload_len;
            let mut packet = Vec::with_capacity(total);
            packet.push(0x45);
            packet.push(0);
            packet.extend_from_slice(&(total as u16).to_be_bytes());
            packet.extend_from_slice(&[0, 0]); // identification
            packet.extend_from_slice(&[0x40, 0x00]); // DF, no fragment
            packet.push(hop_limit);
            packet.push(protocol);
            packet.extend_from_slice(&[0, 0]); // checksum placeholder
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            let header_checksum = internet_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            packet
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            if payload_len > usize::from(u16::MAX) {
                return Err(IpError::Malformed(format!(
                    "{} bytes exceeds the IPv6 payload maximum of {}",
                    payload_len,
                    usize::from(u16::MAX)
                )));
            }
            let mut packet = Vec::with_capacity(40 + payload_len);
            packet.push(0x60);
            packet.extend_from_slice(&[0, 0, 0]); // traffic class / flow label
            packet.extend_from_slice(&(payload_len as u16).to_be_bytes());
            packet.push(protocol);
            packet.push(hop_limit);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            packet
        }
        _ => {
            return Err(IpError::Malformed(
                "source and destination are different address families".to_string(),
            ));
        }
    };
    let header_len = packet.len();
    write_payload(&mut packet);
    debug_assert_eq!(packet.len(), header_len + payload_len);
    Ok(packet)
}

/// Build one IPv4 or IPv6 packet carrying one UDP datagram.
pub fn build_udp_packet(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    hop_limit: u8,
) -> Result<Vec<u8>, IpError> {
    let udp_len = 8 + payload.len();
    build_packet_with(src, dst, IPPROTO_UDP, udp_len, hop_limit, |packet| {
        let start = packet.len();
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        let udp = &mut packet[start..];
        let checksum = transport_checksum(src, dst, IPPROTO_UDP, udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    })
}

/// The RFC 1071 one's-complement sum used by both checksums.
fn checksum_accumulate(parts: &[&[u8]]) -> u32 {
    let mut sum = 0u32;
    for bytes in parts {
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let [last] = chunks.remainder() {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
    }
    sum
}

/// Fold the 32-bit sum to its 16-bit one's-complement value (`0xffff` when the
/// bytes already add up to zero, which is what a checksum field is checked
/// against).
fn checksum_fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    !checksum_fold(checksum_accumulate(&[bytes]))
}

/// Plain RFC 1071 checksum over `bytes` (no pseudo-header).
///
/// ICMPv4 uses this form; TCP, UDP and ICMPv6 checksums are computed with
/// [`transport_checksum`], which adds the IPv4/IPv6 pseudo-header.
pub fn checksum16(bytes: &[u8]) -> u16 {
    internet_checksum(bytes)
}

/// UDP checksum over the IPv4/IPv6 pseudo-header. `udp` carries its checksum
/// field (zero while computing). A result of zero is sent as `0xffff` for
/// IPv6, where a zero checksum means "none".
/// The pseudo-header checksum of one transport segment (UDP or TCP). The
/// segment must carry a zero checksum field while computing; a result of zero
/// is returned as `0xffff` for IPv6, where a zero TCP/UDP checksum means
/// "none".
pub fn transport_checksum(src: IpAddr, dst: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    let sum = transport_checksum_sum(src, dst, protocol, segment);
    let checksum = !checksum_fold(sum);
    if checksum == 0 && src.is_ipv6() {
        0xffff
    } else {
        checksum
    }
}

/// Whether the checksum field of `segment` is correct (the folded sum of the
/// pseudo-header and the segment, checksum field included, is `0xffff`).
pub fn transport_checksum_valid(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    segment: &[u8],
) -> bool {
    checksum_fold(transport_checksum_sum(src, dst, protocol, segment)) == 0xffff
}

fn udp_checksum_valid(src: IpAddr, dst: IpAddr, udp: &[u8]) -> bool {
    transport_checksum_valid(src, dst, IPPROTO_UDP, udp)
}

fn transport_checksum_sum(src: IpAddr, dst: IpAddr, protocol: u8, segment: &[u8]) -> u32 {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => checksum_accumulate(&[
            &src.octets(),
            &dst.octets(),
            &[0, protocol],
            &(segment.len() as u16).to_be_bytes(),
            segment,
        ]),
        (IpAddr::V6(src), IpAddr::V6(dst)) => checksum_accumulate(&[
            &src.octets(),
            &dst.octets(),
            &(segment.len() as u32).to_be_bytes(),
            &[0, 0, 0, protocol],
            segment,
        ]),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn v6(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    #[test]
    fn prefix_parsing_matches_the_pinned_defaults() {
        let host4 = IpPrefix::parse("172.16.0.2").unwrap();
        assert_eq!(host4.addr, IpAddr::V4(v4("172.16.0.2")));
        assert_eq!(host4.bits, 32);
        let host6 = IpPrefix::parse("fd00::2").unwrap();
        assert_eq!(host6.bits, 128);
        let subnet = IpPrefix::parse("192.0.2.7/24").unwrap();
        assert_eq!(subnet.network(), IpAddr::V4(v4("192.0.2.0")));
        assert!(subnet.contains(IpAddr::V4(v4("192.0.2.99"))));
        assert!(!subnet.contains(IpAddr::V4(v4("192.0.3.1"))));
        assert!(!subnet.contains(IpAddr::V6(v6("::1"))));
        assert!(IpPrefix::parse("192.0.2.1/33").is_err());
        assert!(IpPrefix::parse("fd00::1/129").is_err());
        assert!(IpPrefix::parse("not-an-address").is_err());
        assert!(IpPrefix::parse("").is_err());
    }

    /// Vectors computed independently with Python's `socket`/manual RFC 1071
    /// arithmetic (the script is in `tool/kernel-compat/evidence/t18-feasibility.json`).
    #[test]
    fn ipv4_udp_packet_matches_an_independent_vector() {
        let packet = build_udp_packet(
            IpAddr::V4(v4("172.16.0.2")),
            IpAddr::V4(v4("198.51.100.7")),
            45000,
            5353,
            b"abc",
            64,
        )
        .unwrap();
        assert_eq!(
            packet,
            vec![
                0x45, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x64, 0x81, 0xac, 0x10,
                0x00, 0x02, 0xc6, 0x33, 0x64, 0x07, 0xaf, 0xc8, 0x14, 0xe9, 0x00, 0x0b, 0xa0, 0x76,
                0x61, 0x62, 0x63,
            ]
        );
        let parsed = parse_ip_packet(&packet).unwrap();
        let udp = parse_udp(&parsed).unwrap();
        assert_eq!(udp.src_port, 45000);
        assert_eq!(udp.dst_port, 5353);
        assert_eq!(udp.payload, b"abc");
    }

    #[test]
    fn ipv4_round_trip_and_checksum_rejection() {
        let packet = build_udp_packet(
            IpAddr::V4(v4("10.0.0.1")),
            IpAddr::V4(v4("10.0.0.2")),
            1000,
            2000,
            &vec![0x5a; 1400],
            64,
        )
        .unwrap();
        let parsed = parse_ip_packet(&packet).unwrap();
        let udp = parse_udp(&parsed).unwrap();
        assert_eq!(udp.payload.len(), 1400);
        assert_eq!(udp.src_port, 1000);

        let mut corrupt = packet.clone();
        corrupt[10] ^= 0xff; // header checksum
        assert!(matches!(
            parse_ip_packet(&corrupt),
            Err(IpError::Malformed(reason)) if reason.contains("header checksum")
        ));
        let mut corrupt = packet;
        corrupt[28] ^= 0xff; // UDP checksum
        assert!(parse_udp(&parse_ip_packet(&corrupt).unwrap()).is_err());
    }

    #[test]
    fn ipv6_round_trip_is_mandatory_checksum() {
        let packet = build_udp_packet(
            IpAddr::V6(v6("fd00::2")),
            IpAddr::V6(v6("2001:db8::42")),
            1234,
            443,
            b"hello",
            64,
        )
        .unwrap();
        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.protocol, 17);
        let udp = parse_udp(&parsed).unwrap();
        assert_eq!(udp.payload, b"hello");
        // Independently computed pseudo-header checksum for this datagram.
        assert_eq!(&packet[46..48], &[0x8a, 0x77]);
        let mut zero = packet;
        zero[46] = 0; // the UDP checksum over IPv6 must never be 0
        zero[47] = 0;
        assert!(matches!(
            parse_udp(&parse_ip_packet(&zero).unwrap()),
            Err(IpError::Malformed(reason)) if reason.contains("checksum")
        ));
    }

    #[test]
    fn fragments_and_other_protocols_are_named() {
        let mut packet = build_udp_packet(
            IpAddr::V4(v4("10.0.0.1")),
            IpAddr::V4(v4("10.0.0.2")),
            1,
            2,
            b"x",
            64,
        )
        .unwrap();
        packet[7] = 0x20; // MF set
        assert!(matches!(
            parse_ip_packet(&packet),
            Err(IpError::Unsupported(reason)) if reason.contains("fragment")
        ));

        let mut tcp = build_udp_packet(
            IpAddr::V4(v4("10.0.0.1")),
            IpAddr::V4(v4("10.0.0.2")),
            1,
            2,
            b"x",
            64,
        )
        .unwrap();
        tcp[9] = IPPROTO_TCP;
        tcp[10] = 0;
        tcp[11] = 0;
        let header = internet_checksum(&tcp[..20]);
        tcp[10..12].copy_from_slice(&header.to_be_bytes());
        assert!(matches!(
            parse_udp(&parse_ip_packet(&tcp).unwrap()),
            Err(IpError::Unsupported(reason)) if reason.contains("TCP")
        ));
    }

    #[test]
    fn truncation_and_family_mismatch_are_rejected() {
        assert!(parse_ip_packet(&[]).is_err());
        assert!(parse_ip_packet(&[0x45; 10]).is_err());
        assert!(parse_ip_packet(&[0x60; 39]).is_err());
        assert!(build_udp_packet(
            IpAddr::V4(v4("10.0.0.1")),
            IpAddr::V6(v6("fd00::1")),
            1,
            2,
            b"x",
            64
        )
        .is_err());
        let oversized = vec![0u8; usize::from(u16::MAX)];
        assert!(build_udp_packet(
            IpAddr::V4(v4("10.0.0.1")),
            IpAddr::V4(v4("10.0.0.2")),
            1,
            2,
            &oversized,
            64
        )
        .is_err());
    }
}
