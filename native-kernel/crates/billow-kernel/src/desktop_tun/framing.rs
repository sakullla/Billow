//! utun packet framing.
//!
//! A macOS `utun` descriptor is a packet socket with a 4-byte big-endian
//! address-family header in front of every IP packet (`AF_INET = 2`,
//! `AF_INET6 = 30`). Linux `/dev/net/tun` with `IFF_NO_PI` and Wintun both
//! carry the raw IP packet. The reader strips the header and the writer adds it
//! back; both directions are pure functions so they are testable without a
//! privileged device.

use std::fmt;

/// Darwin `AF_INET`.
pub const UTUN_AF_INET: u32 = 2;
/// Darwin `AF_INET6`.
pub const UTUN_AF_INET6: u32 = 30;
/// Size of the utun address-family header.
pub const UTUN_HEADER: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtunError {
    Empty,
    ShortHeader,
    NotIp,
    UnsupportedFamily(u32),
    FamilyMismatch { af: u32, version: u8 },
}

impl fmt::Display for UtunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtunError::Empty => write!(f, "empty IP packet"),
            UtunError::ShortHeader => write!(f, "utun packet is shorter than the 4-byte address-family header"),
            UtunError::NotIp => write!(f, "packet is not IPv4 or IPv6"),
            UtunError::UnsupportedFamily(af) => write!(f, "utun address family {af} is neither AF_INET (2) nor AF_INET6 (30)"),
            UtunError::FamilyMismatch { af, version } => {
                write!(f, "utun address family {af} does not match IP version {version}")
            }
        }
    }
}

impl std::error::Error for UtunError {}

/// The utun header for a raw IP packet.
pub fn utun_header(packet: &[u8]) -> Result<[u8; UTUN_HEADER], UtunError> {
    let first = *packet.first().ok_or(UtunError::Empty)?;
    let af = match first >> 4 {
        4 => UTUN_AF_INET,
        6 => UTUN_AF_INET6,
        _ => return Err(UtunError::NotIp),
    };
    Ok(af.to_be_bytes())
}

/// Prefix `packet` with the utun header.
pub fn with_utun_header(packet: &[u8]) -> Result<Vec<u8>, UtunError> {
    let header = utun_header(packet)?;
    let mut out = Vec::with_capacity(UTUN_HEADER + packet.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(packet);
    Ok(out)
}

/// Strip and validate the utun header, returning the raw IP packet.
pub fn strip_utun_header(packet: &[u8]) -> Result<&[u8], UtunError> {
    if packet.len() < UTUN_HEADER + 1 {
        return Err(UtunError::ShortHeader);
    }
    let af = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
    let version = packet[UTUN_HEADER] >> 4;
    match (af, version) {
        (UTUN_AF_INET, 4) | (UTUN_AF_INET6, 6) => Ok(&packet[UTUN_HEADER..]),
        (UTUN_AF_INET | UTUN_AF_INET6, _) => Err(UtunError::FamilyMismatch { af, version }),
        _ => Err(UtunError::UnsupportedFamily(af)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_packet() -> Vec<u8> {
        vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 198, 18, 0, 1, 198, 18, 0, 2]
    }

    fn v6_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = 17;
        packet[7] = 64;
        packet
    }

    #[test]
    fn ipv4_uses_af_inet_and_round_trips() {
        let framed = with_utun_header(&v4_packet()).unwrap();
        assert_eq!(&framed[..4], &[0, 0, 0, 2]);
        assert_eq!(strip_utun_header(&framed).unwrap(), v4_packet().as_slice());
    }

    #[test]
    fn ipv6_uses_af_inet6_and_round_trips() {
        let framed = with_utun_header(&v6_packet()).unwrap();
        assert_eq!(&framed[..4], &[0, 0, 0, 30]);
        assert_eq!(strip_utun_header(&framed).unwrap(), v6_packet().as_slice());
    }

    #[test]
    fn malformed_framing_is_named() {
        assert_eq!(strip_utun_header(&[0, 0]), Err(UtunError::ShortHeader));
        assert_eq!(
            strip_utun_header(&[0, 0, 0, 7, 0x45, 0, 0, 20]),
            Err(UtunError::UnsupportedFamily(7))
        );
        assert_eq!(
            strip_utun_header(&[0, 0, 0, 2, 0x60, 0, 0, 40]),
            Err(UtunError::FamilyMismatch { af: 2, version: 6 })
        );
        assert_eq!(with_utun_header(&[]), Err(UtunError::Empty));
        assert_eq!(with_utun_header(&[0x10]), Err(UtunError::NotIp));
    }
}
