//! age-encrypted subscriptions.
//!
//! Some providers publish the config encrypted to the user's age public key. Each
//! subscription can carry one or more X25519 identities (`AGE-SECRET-KEY-1…`); a
//! fetched body that is an age file — binary or ASCII-armored — is decrypted before
//! the usual base64/YAML normalization. Plain bodies pass through untouched.

use std::io::Read;
use std::str::FromStr;

use age::x25519;
use base64::Engine;

const BINARY_MAGIC: &[u8] = b"age-encryption.org/v1";
const ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_END: &str = "-----END AGE ENCRYPTED FILE-----";
/// Decrypted configs are capped like fetched ones so a hostile file cannot balloon.
const PLAINTEXT_LIMIT: u64 = 32 * 1024 * 1024;

pub const KEY_FORMAT_ERROR: &str = "age 私钥格式不正确：每行一个以 AGE-SECRET-KEY-1 开头的私钥，# 开头的行视为注释";
pub const KEY_MISSING_ERROR: &str = "订阅内容已使用 age 加密，请在「编辑配置信息」中填写 age 私钥后重新更新";
pub const KEY_MISMATCH_ERROR: &str = "已填写的 age 私钥无法解密该订阅，请确认私钥与订阅提供方使用的公钥匹配";
pub const CORRUPT_ERROR: &str = "age 加密内容不完整或已损坏，无法解密";
pub const PLAINTEXT_ERROR: &str = "age 解密后的内容不是有效的文本配置";

/// Lines that are neither blank nor `#` comments; `age-keygen` output pastes as-is.
fn key_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Every non-comment line must be an X25519 identity; an empty text means "no key".
pub fn parse_identities(text: &str) -> Result<Vec<x25519::Identity>, String> {
    key_lines(text)
        .map(|line| x25519::Identity::from_str(line).map_err(|_| KEY_FORMAT_ERROR.to_string()))
        .collect()
}

/// Canonical form kept on disk: one identity per line, comments dropped.
pub fn normalize_keys(text: &str) -> Result<String, String> {
    let lines: Vec<&str> = key_lines(text).collect();
    parse_identities(text)?;
    Ok(lines.join("\n"))
}

/// Public keys (`age1…`) for display; the secret never leaves the backend.
pub fn recipients(text: &str) -> Vec<String> {
    parse_identities(text)
        .map(|identities| identities.iter().map(|identity| identity.to_public().to_string()).collect())
        .unwrap_or_default()
}

pub fn is_encrypted_bytes(body: &[u8]) -> bool {
    body.starts_with(BINARY_MAGIC)
}

pub fn is_encrypted_text(content: &str) -> bool {
    let trimmed = content.trim_start_matches('\u{feff}').trim_start();
    trimmed.starts_with(ARMOR_BEGIN) || trimmed.starts_with("age-encryption.org/v1")
}

/// Binary age files are not UTF-8; armor them so the subscription pipeline stays textual.
pub fn armor_binary(body: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 64 + 80);
    out.push_str(ARMOR_BEGIN);
    out.push('\n');
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out.push('\n');
    out
}

/// Decrypt when the content is an age file; anything else is returned unchanged.
pub fn decrypt_if_needed(content: &str, keys: &str) -> Result<String, String> {
    if !is_encrypted_text(content) {
        return Ok(content.to_string());
    }
    let identities = parse_identities(keys).map_err(|_| KEY_FORMAT_ERROR.to_string())?;
    if identities.is_empty() {
        return Err(KEY_MISSING_ERROR.to_string());
    }
    let trimmed = content.trim_start_matches('\u{feff}').trim();
    let mut normalized = trimmed.replace("\r\n", "\n");
    if !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    let reader = age::armor::ArmoredReader::new(normalized.as_bytes());
    let decryptor = age::Decryptor::new(reader).map_err(|_| CORRUPT_ERROR.to_string())?;
    let mut stream = decryptor
        .decrypt(identities.iter().map(|identity| identity as &dyn age::Identity))
        .map_err(|error| match error {
            age::DecryptError::NoMatchingKeys => KEY_MISMATCH_ERROR.to_string(),
            _ => CORRUPT_ERROR.to_string(),
        })?;
    let mut plain = Vec::new();
    (&mut stream)
        .take(PLAINTEXT_LIMIT + 1)
        .read_to_end(&mut plain)
        .map_err(|_| CORRUPT_ERROR.to_string())?;
    if plain.len() as u64 > PLAINTEXT_LIMIT {
        return Err(CORRUPT_ERROR.to_string());
    }
    String::from_utf8(plain).map_err(|_| PLAINTEXT_ERROR.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::io::Write;

    fn secret(identity: &x25519::Identity) -> String {
        identity.to_string().expose_secret().to_string()
    }

    fn encrypt(plain: &str, recipient: &x25519::Recipient, armor: bool) -> Vec<u8> {
        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient)).unwrap();
        let mut out = Vec::new();
        if armor {
            let armored = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor).unwrap();
            let mut writer = encryptor.wrap_output(armored).unwrap();
            writer.write_all(plain.as_bytes()).unwrap();
            writer.finish().unwrap().finish().unwrap();
        } else {
            let mut writer = encryptor.wrap_output(&mut out).unwrap();
            writer.write_all(plain.as_bytes()).unwrap();
            writer.finish().unwrap();
        }
        out
    }

    #[test]
    fn decrypts_armored_and_binary_files_with_a_matching_key() {
        let identity = x25519::Identity::generate();
        let keys = format!("# created: 2026-11-16\n# public key: {}\n{}\n", identity.to_public(), secret(&identity));
        let config = "proxies: []\nproxy-groups: []\nrules: []\n";

        let armored = String::from_utf8(encrypt(config, &identity.to_public(), true)).unwrap();
        assert!(is_encrypted_text(&armored));
        assert_eq!(decrypt_if_needed(&armored, &keys).unwrap(), config);

        let binary = encrypt(config, &identity.to_public(), false);
        assert!(is_encrypted_bytes(&binary));
        assert!(String::from_utf8(binary.clone()).is_err() || !binary.is_empty());
        let wrapped = armor_binary(&binary);
        assert_eq!(decrypt_if_needed(&wrapped, &keys).unwrap(), config);

        // CRLF line endings from Windows servers still decrypt.
        let crlf = armored.replace('\n', "\r\n");
        assert_eq!(decrypt_if_needed(&crlf, &keys).unwrap(), config);
    }

    #[test]
    fn explains_missing_mismatched_and_corrupt_inputs() {
        let identity = x25519::Identity::generate();
        let other = x25519::Identity::generate();
        let armored = String::from_utf8(encrypt("a: 1\n", &identity.to_public(), true)).unwrap();

        assert_eq!(decrypt_if_needed(&armored, "").unwrap_err(), KEY_MISSING_ERROR);
        assert_eq!(
            decrypt_if_needed(&armored, &secret(&other)).unwrap_err(),
            KEY_MISMATCH_ERROR
        );
        // One of several keys matching is enough (key rotation).
        let both = format!("{}\n{}", secret(&other), secret(&identity));
        assert_eq!(decrypt_if_needed(&armored, &both).unwrap(), "a: 1\n");

        let truncated = format!("{ARMOR_BEGIN}\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCg==\n{ARMOR_END}\n");
        assert_eq!(decrypt_if_needed(&truncated, &secret(&identity)).unwrap_err(), CORRUPT_ERROR);

        // Plain configs are untouched, even with no key.
        assert_eq!(decrypt_if_needed("proxies: []\n", "").unwrap(), "proxies: []\n");
    }

    #[test]
    fn validates_and_normalizes_keys_and_derives_public_keys() {
        let identity = x25519::Identity::generate();
        let secret = secret(&identity);
        let pasted = format!("# created: now\n\n  {secret}  \n");
        assert_eq!(normalize_keys(&pasted).unwrap(), secret);
        assert_eq!(recipients(&pasted), vec![identity.to_public().to_string()]);
        assert_eq!(normalize_keys("").unwrap(), "");
        assert_eq!(normalize_keys("AGE-SECRET-KEY-1NOTAKEY").unwrap_err(), KEY_FORMAT_ERROR);
        assert_eq!(normalize_keys("age1publickeyisnotsecret").unwrap_err(), KEY_FORMAT_ERROR);
    }
}
