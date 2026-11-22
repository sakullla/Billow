//! Cloudflare WARP material for the pinned `masque` adapter
//! (`transport/masque/masque.go`): the base64 ECDSA private key becomes a
//! self-signed client certificate, the base64 endpoint public key pins the
//! peer certificate, and the TLS configuration sends the certificate while
//! verifying only that pin.
//!
//! The pinned Go code is not copied (it is GPL-3.0); the shapes here are the
//! ones the WARP endpoint accepts, as recorded from the pinned adapter's
//! fields and its black-box behaviour:
//!
//! * `private-key` is base64 of a SEC1 `ECPrivateKey` (what
//!   `x509.ParseECPrivateKey` reads); `public-key` is base64 of a DER
//!   `SubjectPublicKeyInfo` (what `x509.ParsePKIXPublicKey` reads). Both are
//!   P-256 in every WARP registration; other curves are refused by name.
//! * The client certificate is self-signed: serial 0, empty issuer and
//!   subject, one-day validity, ecdsa-with-SHA256. The pinned code builds the
//!   same certificate with `x509.CreateCertificate` and a zero template.
//! * Certificate *names* are not verified (the pinned adapter sets
//!   `InsecureSkipVerify` because the SNI is not the endpoint's name); the
//!   endpoint is authenticated by comparing the peer certificate's
//!   SubjectPublicKeyInfo with `public-key`. `skip-cert-verify: true` drops
//!   that pin, exactly like the pinned option.
//!
//! No new dependency is used: base64, DER and the calendar conversion are
//! implemented here (kept small and unit-tested against generated keys), the
//! signature comes from `ring` (already the TLS provider).

use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

/// DER of the `id-ecPublicKey` OID (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// DER of the `prime256v1` OID (1.2.840.10045.3.1.7).
const OID_PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER of the `ecdsa-with-SHA256` OID (1.2.840.10045.4.3.2).
const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// A parsed WARP client identity: the PKCS#8 form rustls/ring sign with, the
/// uncompressed P-256 point and its SubjectPublicKeyInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpIdentity {
    pub pkcs8: Vec<u8>,
    pub point: Vec<u8>,
    pub spki: Vec<u8>,
}

/// Decode a `private-key` value into its signing form. Accepts the pinned
/// SEC1 `ECPrivateKey` and (as a superset) a PKCS#8 wrapper of one.
pub fn parse_private_key(base64_text: &str) -> Result<WarpIdentity, String> {
    let der = base64_decode(base64_text).map_err(|e| format!("option 'private-key': {e}"))?;
    let sec1 = sec1_of_pkcs8(&der).unwrap_or_else(|| der.clone());
    let scalar = sec1_private_key(&sec1)
        .ok_or_else(|| "option 'private-key': not a SEC1 EC private key".to_string())?;
    if scalar.len() != 32 {
        return Err(format!(
            "option 'private-key': {}-byte scalar is not a P-256 key (32 bytes expected); only P-256 WARP registrations are supported",
            scalar.len()
        ));
    }
    let pkcs8 = pkcs8_of_sec1(&sec1);
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng)
        .map_err(|_| "option 'private-key': not a P-256 ECDSA private key".to_string())?;
    let point = key.public_key().as_ref().to_vec();
    let spki = spki_of_point(&point);
    Ok(WarpIdentity { pkcs8, point, spki })
}

/// Decode a `public-key` value (DER SubjectPublicKeyInfo) and check it is an
/// ECDSA P-256 key, as the pinned adapter does.
pub fn parse_public_key(base64_text: &str) -> Result<Vec<u8>, String> {
    let der = base64_decode(base64_text).map_err(|e| format!("option 'public-key': {e}"))?;
    let mut outer = DerReader::new(&der);
    let (tag, content) = outer
        .next()
        .ok_or_else(|| "option 'public-key': not a DER SubjectPublicKeyInfo".to_string())?;
    if tag != 0x30 || !outer.is_empty() {
        return Err("option 'public-key': not a DER SubjectPublicKeyInfo".to_string());
    }
    let mut fields = DerReader::new(content);
    let (algorithm_tag, algorithm) = fields
        .next()
        .ok_or_else(|| "option 'public-key': missing the algorithm".to_string())?;
    if algorithm_tag != 0x30 {
        return Err("option 'public-key': missing the algorithm".to_string());
    }
    let mut algorithm_fields = DerReader::new(algorithm);
    let first = algorithm_fields
        .next()
        .map(|(tag, value)| (tag, value.to_vec()));
    let second = algorithm_fields
        .next()
        .map(|(tag, value)| (tag, value.to_vec()));
    if first.as_ref().map(|(tag, value)| (*tag, value.as_slice()))
        != Some((0x06, &OID_EC_PUBLIC_KEY[2..]))
        || second.as_ref().map(|(tag, value)| (*tag, value.as_slice()))
            != Some((0x06, &OID_PRIME256V1[2..]))
    {
        return Err(
            "option 'public-key': only ECDSA P-256 endpoint keys are supported".to_string(),
        );
    }
    let (bits_tag, bits) = fields
        .next()
        .ok_or_else(|| "option 'public-key': missing the public key bits".to_string())?;
    if bits_tag != 0x03 || bits.first() != Some(&0) || bits.len() != 66 || bits[1] != 0x04 {
        return Err("option 'public-key': the public key point is not a P-256 point".to_string());
    }
    Ok(der)
}

/// Build the self-signed client certificate the WARP endpoint expects.
pub fn client_certificate(identity: &WarpIdentity) -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &identity.pkcs8, &rng)
        .map_err(|_| "the private key cannot sign".to_string())?;
    let not_before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    // x509.CreateCertificate with a one-day NotAfter in the pinned template.
    let not_after = not_before + 24 * 60 * 60;
    let tbs = tbs_certificate(identity, not_before, not_after);
    let signature = key
        .sign(&rng, &tbs)
        .map_err(|_| "the private key cannot sign".to_string())?;
    let mut certificate = Vec::new();
    let mut fields = Vec::new();
    fields.extend_from_slice(&tbs);
    fields.extend_from_slice(&der_tlv(0x30, OID_ECDSA_SHA256));
    let mut bits = vec![0u8];
    bits.extend_from_slice(signature.as_ref());
    fields.extend_from_slice(&der_tlv(0x03, &bits));
    certificate.extend_from_slice(&der_tlv(0x30, &fields));
    Ok(certificate)
}

/// The DER SubjectPublicKeyInfo carried by `certificate`.
pub fn spki_of_certificate(certificate: &[u8]) -> Option<Vec<u8>> {
    let mut outer = DerReader::new(certificate);
    let (tag, content) = outer.next()?;
    if tag != 0x30 {
        return None;
    }
    let mut certificate_fields = DerReader::new(content);
    let (tag, tbs) = certificate_fields.next()?;
    if tag != 0x30 {
        return None;
    }
    let mut fields = DerReader::new(tbs);
    // [0] EXPLICIT version is optional.
    let mut next = fields.next()?;
    if next.0 == 0xa0 {
        next = fields.next()?;
    }
    // serialNumber, signature, issuer, validity, subject, then SPKI.
    if next.0 != 0x02 {
        return None;
    }
    for _ in 0..4 {
        fields.next()?;
    }
    let start = fields.pos();
    let (tag, _) = fields.next()?;
    if tag != 0x30 {
        return None;
    }
    // Re-encode the TLV (tag and length included): the pin is an encoded SPKI.
    let end = fields.pos();
    tbs.get(start..end).map(|bytes| bytes.to_vec())
}

fn tbs_certificate(identity: &WarpIdentity, not_before: u64, not_after: u64) -> Vec<u8> {
    let mut version = Vec::new();
    version.extend_from_slice(&der_tlv(0x02, &[2])); // v3
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&der_tlv(0xa0, &version));
    tbs.extend_from_slice(&der_tlv(0x02, &[0])); // serialNumber 0
    tbs.extend_from_slice(&der_tlv(0x30, OID_ECDSA_SHA256)); // signature
    tbs.extend_from_slice(&der_tlv(0x30, &[])); // issuer: empty Name
    let mut validity = Vec::new();
    validity.extend_from_slice(&der_tlv(0x17, utc_time(not_before).as_bytes()));
    validity.extend_from_slice(&der_tlv(0x17, utc_time(not_after).as_bytes()));
    tbs.extend_from_slice(&der_tlv(0x30, &validity));
    tbs.extend_from_slice(&der_tlv(0x30, &[])); // subject: empty Name
    tbs.extend_from_slice(&identity.spki);
    der_tlv(0x30, &tbs)
}

fn utc_time(unix: u64) -> String {
    let (year, month, day, hour, minute, second) = civil_time(unix);
    format!(
        "{:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z",
        year % 100
    )
}

/// days-from-civil (Howard Hinnant's algorithm), UTC only.
fn civil_time(unix: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (unix / 86_400) as i64;
    let seconds = unix % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (
        year,
        m,
        d,
        (seconds / 3600) as u32,
        ((seconds % 3600) / 60) as u32,
        (seconds % 60) as u32,
    )
}

/// The TLS client configuration for the WARP endpoint: TLS 1.3 only, the
/// generated client certificate, and a verifier that accepts the peer only
/// when its SubjectPublicKeyInfo equals `pin` (unless `skip_cert_verify`
/// dropped the pin, like the pinned option).
pub fn client_config(
    pin: Option<Vec<u8>>,
    identity: &WarpIdentity,
    alpn: &[String],
    enable_sni: bool,
) -> io::Result<Arc<ClientConfig>> {
    let provider = Arc::new(ring_provider::default_provider());
    let certificate = client_certificate(identity).map_err(io::Error::other)?;
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?;
    let verifier = Arc::new(PinnedEndpointKey {
        pin,
        provider: provider.clone(),
    });
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(certificate)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.pkcs8.clone())),
        )
        .map_err(io::Error::other)?;
    config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    config.enable_sni = enable_sni;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinnedEndpointKey {
    pin: Option<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedEndpointKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The pinned adapter sets InsecureSkipVerify and checks only the key;
        // the chain and the certificate name are not verified either way.
        let Some(pin) = &self.pin else {
            return Ok(ServerCertVerified::assertion());
        };
        match spki_of_certificate(end_entity.as_ref()) {
            Some(spki) if spki == *pin => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::General(
                "masque: the endpoint certificate does not carry the pinned public key".to_string(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Minimal DER and base64.
// ---------------------------------------------------------------------------

struct DerReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> DerReader<'a> {
        DerReader { bytes, pos: 0 }
    }

    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.bytes.get(self.pos..)?.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (length, header) = if first < 0x80 {
            (usize::from(first), 1)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return None;
            }
            let bytes = rest.get(..count)?;
            let mut length = 0usize;
            for byte in bytes {
                length = (length << 8) | usize::from(*byte);
            }
            (length, 1 + count)
        };
        let start = self.pos + 1 + header;
        let end = start.checked_add(length)?;
        let value = self.bytes.get(start..end)?;
        self.pos = end;
        Some((tag, value))
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn pos(&self) -> usize {
        self.pos
    }
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        vec![length as u8]
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
        let significant = &bytes[first..];
        let mut out = Vec::with_capacity(1 + significant.len());
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
        out
    }
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tag);
    out.extend_from_slice(&der_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// The inner SEC1 `ECPrivateKey` of a PKCS#8 wrapper (`None` when `der` is not
/// one).
pub fn sec1_of_pkcs8(der: &[u8]) -> Option<Vec<u8>> {
    let mut outer = DerReader::new(der);
    let (tag, content) = outer.next()?;
    if tag != 0x30 {
        return None;
    }
    let mut fields = DerReader::new(content);
    let (version_tag, version) = fields.next()?;
    if version_tag != 0x02 || version != [0] {
        return None;
    }
    let (algorithm_tag, algorithm) = fields.next()?;
    if algorithm_tag != 0x30 {
        return None;
    }
    let mut algorithm_fields = DerReader::new(algorithm);
    let first = algorithm_fields.next()?;
    let second = algorithm_fields.next()?;
    if first.0 != 0x06 || second.0 != 0x06 {
        return None;
    }
    let (key_tag, key) = fields.next()?;
    if key_tag != 0x04 {
        return None;
    }
    // The inner value must itself be a SEC1 ECPrivateKey sequence.
    let mut inner = DerReader::new(key);
    let (inner_tag, _) = inner.next()?;
    if inner_tag != 0x30 {
        return None;
    }
    Some(key.to_vec())
}

fn sec1_private_key(sec1: &[u8]) -> Option<Vec<u8>> {
    let mut outer = DerReader::new(sec1);
    let (tag, content) = outer.next()?;
    if tag != 0x30 {
        return None;
    }
    let mut fields = DerReader::new(content);
    let (version_tag, version) = fields.next()?;
    if version_tag != 0x02 || version != [1] {
        return None;
    }
    let (key_tag, key) = fields.next()?;
    if key_tag != 0x04 {
        return None;
    }
    // An explicit P-384/P-521 key is refused here rather than being truncated.
    if let Some((curve_tag, curve)) = fields.next() {
        if curve_tag == 0xa0 {
            let mut inner = DerReader::new(curve);
            if let Some((oid_tag, oid)) = inner.next() {
                if oid_tag == 0x06 && oid != &OID_PRIME256V1[2..] {
                    return None;
                }
            }
        }
    }
    Some(key.to_vec())
}

fn pkcs8_of_sec1(sec1: &[u8]) -> Vec<u8> {
    let mut algorithm = Vec::new();
    algorithm.extend_from_slice(OID_EC_PUBLIC_KEY);
    algorithm.extend_from_slice(OID_PRIME256V1);
    let mut fields = Vec::new();
    fields.extend_from_slice(&der_tlv(0x02, &[0]));
    fields.extend_from_slice(&der_tlv(0x30, &algorithm));
    fields.extend_from_slice(&der_tlv(0x04, sec1));
    der_tlv(0x30, &fields)
}

fn spki_of_point(point: &[u8]) -> Vec<u8> {
    let mut algorithm = Vec::new();
    algorithm.extend_from_slice(OID_EC_PUBLIC_KEY);
    algorithm.extend_from_slice(OID_PRIME256V1);
    let mut fields = Vec::new();
    fields.extend_from_slice(&der_tlv(0x30, &algorithm));
    let mut bits = vec![0u8];
    bits.extend_from_slice(point);
    fields.extend_from_slice(&der_tlv(0x03, &bits));
    der_tlv(0x30, &fields)
}

/// Standard base64 (RFC 4648 §4) with `=` padding; whitespace is ignored.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for byte in text.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return Err("base64 data after padding".to_string());
        }
        let value = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(format!("invalid base64 character '{}'", byte as char)),
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    if padding > 2 {
        return Err("too much base64 padding".to_string());
    }
    let leftover = (bits % 8) as usize;
    let valid = match padding {
        0 => leftover == 0,
        1 => leftover == 2,
        _ => leftover == 4,
    };
    if !valid {
        return Err("invalid base64 length or padding".to_string());
    }
    Ok(out)
}

/// Standard base64 encoding with padding (used to write test vectors and the
/// `public-key` value of a captured endpoint certificate).
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).map(|byte| u32::from(*byte));
        let third = chunk.get(2).map(|byte| u32::from(*byte));
        let triple = (first << 16) | (second.unwrap_or(0) << 8) | third.unwrap_or(0);
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        if second.is_some() {
            out.push(ALPHABET[(triple >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if third.is_some() {
            out.push(ALPHABET[triple as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::UnparsedPublicKey;

    fn generated_identity() -> (WarpIdentity, Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let sec1 = sec1_of_pkcs8(pkcs8.as_ref()).expect("ring emits a SEC1 inner key");
        let identity = parse_private_key(&base64_encode(&sec1)).unwrap();
        (identity, sec1, pkcs8.as_ref().to_vec())
    }

    #[test]
    fn a_sec1_private_key_round_trips_through_the_pkcs8_form() {
        let (identity, sec1, pkcs8) = generated_identity();
        assert_eq!(identity.point.len(), 65);
        assert_eq!(identity.point[0], 0x04);
        assert_eq!(spki_of_point(&identity.point), identity.spki);
        assert_eq!(
            sec1_of_pkcs8(&identity.pkcs8).as_deref(),
            Some(sec1.as_slice())
        );
        assert_eq!(parse_private_key(&base64_encode(&pkcs8)).unwrap(), identity);
    }

    #[test]
    fn the_public_key_pin_is_the_encoded_spki() {
        let (identity, _, _) = generated_identity();
        let decoded = parse_public_key(&base64_encode(&identity.spki)).unwrap();
        assert_eq!(decoded, identity.spki);
        // Whitespace is accepted, as the pinned Go decoder tolerates it.
        let wrapped = format!(
            "{}\n{}",
            &base64_encode(&identity.spki)[..20],
            &base64_encode(&identity.spki)[20..]
        );
        assert_eq!(parse_public_key(&wrapped).unwrap(), identity.spki);
    }

    #[test]
    fn non_p256_and_garbage_keys_are_refused_by_name() {
        // A SEC1 key whose explicit parameters name secp384r1 is rejected
        // instead of being truncated to 32 bytes.
        let mut sec1 = Vec::new();
        sec1.extend_from_slice(&der_tlv(0x02, &[1]));
        sec1.extend_from_slice(&der_tlv(0x04, &[0x11; 48]));
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&der_tlv(0x06, &[0x2b, 0x81, 0x04, 0x00, 0x22]));
        sec1.extend_from_slice(&der_tlv(0xa0, &parameters));
        let sec1 = der_tlv(0x30, &sec1);
        assert!(parse_private_key(&base64_encode(&sec1)).is_err());

        assert!(parse_private_key("not base64!")
            .unwrap_err()
            .contains("base64"));
        assert!(parse_public_key("AAAA")
            .unwrap_err()
            .contains("SubjectPublicKeyInfo"));
        // A P-384 SPKI (ecPublicKey + secp384r1) is a well-formed SPKI this
        // kernel refuses instead of mis-verifying.
        let mut algorithm = Vec::new();
        algorithm.extend_from_slice(OID_EC_PUBLIC_KEY);
        algorithm.extend_from_slice(&der_tlv(0x06, &[0x2b, 0x81, 0x04, 0x00, 0x22]));
        let mut fields = Vec::new();
        fields.extend_from_slice(&der_tlv(0x30, &algorithm));
        let mut bits = vec![0u8];
        bits.extend_from_slice(&[0x04; 97]);
        fields.extend_from_slice(&der_tlv(0x03, &bits));
        let p384 = der_tlv(0x30, &fields);
        assert!(parse_public_key(&base64_encode(&p384))
            .unwrap_err()
            .contains("P-256"));
    }

    #[test]
    fn the_client_certificate_carries_the_key_and_a_valid_self_signature() {
        let (identity, _, _) = generated_identity();
        let certificate = client_certificate(&identity).unwrap();
        // The SPKI the peer reads is the identity's own SPKI.
        assert_eq!(spki_of_certificate(&certificate).unwrap(), identity.spki);

        // Signature: the outer sequence's last element is the BIT STRING; the
        // first is the TBS whose bytes the signature covers. Verify with ring.
        let mut outer = DerReader::new(&certificate);
        let (_, content) = outer.next().unwrap();
        let mut fields = DerReader::new(content);
        let (_, tbs) = fields.next().unwrap();
        let (tag, algorithm) = fields.next().unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(algorithm, OID_ECDSA_SHA256);
        let (tag, bits) = fields.next().unwrap();
        assert_eq!(tag, 0x03);
        assert_eq!(bits[0], 0);
        let mut tbs_tlv = Vec::new();
        // Re-encode the TBS TLV so the verified bytes are exactly what the
        // certificate contains (the signature covers the TLV, not the value).
        tbs_tlv.extend_from_slice(&der_tlv(0x30, tbs));
        UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, &identity.point)
            .verify(&tbs_tlv, &bits[1..])
            .expect("the client certificate is signed by the configured key");

        // Deterministic structure: serial 0, empty names, one-day validity.
        assert!(certificate
            .windows(3)
            .any(|window| window == [0x02, 0x01, 0x00]));
    }

    #[test]
    fn utc_time_formats_calendar_dates() {
        assert_eq!(utc_time(0), "700101000000Z");
        assert_eq!(utc_time(1_767_225_600), "260101000000Z");
        assert_eq!(utc_time(1_767_311_999), "260101235959Z");
        assert_eq!(utc_time(1_735_689_600), "250101000000Z");
    }

    #[test]
    fn base64_round_trip_and_padding_rules() {
        for bytes in [&b""[..], &b"f"[..], &b"fo"[..], &b"foo"[..], &b"foobar"[..]] {
            assert_eq!(base64_decode(&base64_encode(bytes)).unwrap(), bytes);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert!(base64_decode("Zg===").is_err());
        assert!(base64_decode("Z").is_err());
        assert!(base64_decode("Zg==Zg==").is_err());
    }
}
