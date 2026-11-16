//! Streaming, integrity-checked extraction of build-time compressed resources.
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_RESOURCE: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct PackedResource {
    pub file: String,
    pub sha256: String,
    pub size: u64,
    pub unpacked_sha256: String,
    pub unpacked_size: u64,
}

struct HashReader<R> {
    source: R,
    hash: Sha256,
    size: u64,
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = self.source.read(buffer)?;
        self.hash.update(&buffer[..size]);
        self.size += size as u64;
        Ok(size)
    }
}

/// Decode into a sibling temporary file. Never replace an existing file until
/// both hashes, both lengths and the format-specific validation have passed.
pub fn unpack(
    source: impl Read,
    destination: &Path,
    metadata: &PackedResource,
    validate: impl FnOnce(&Path) -> bool,
) -> io::Result<()> {
    let valid_hash = |hash: &str| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit());
    if metadata.size == 0 || metadata.size > MAX_RESOURCE
        || metadata.unpacked_size == 0 || metadata.unpacked_size > MAX_RESOURCE
        || !valid_hash(&metadata.sha256) || !valid_hash(&metadata.unpacked_sha256) {
        return Err(io::Error::other("内置资源清单无效"));
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let temporary = destination.with_extension(format!("unpack-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let result = (|| {
        let mut source = HashReader { source: source.take(metadata.size + 1), hash: Sha256::new(), size: 0 };
        let mut output = File::create(&temporary)?;
        let mut hash = Sha256::new();
        let mut size = 0u64;
        {
            let mut decoded = brotli_decompressor::Decompressor::new(&mut source, 64 * 1024)
                .take(metadata.unpacked_size + 1);
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let length = decoded.read(&mut buffer)?;
                if length == 0 { break; }
                size += length as u64;
                if size > metadata.unpacked_size { return Err(io::Error::other("内置资源解压长度超出清单")); }
                hash.update(&buffer[..length]);
                output.write_all(&buffer[..length])?;
            }
        }
        // Include any buffered/trailing bytes in the compressed-file integrity check.
        io::copy(&mut source, &mut io::sink())?;
        if size != metadata.unpacked_size || source.size != metadata.size
            || format!("{:x}", hash.finalize()) != metadata.unpacked_sha256.to_ascii_lowercase()
            || format!("{:x}", source.hash.finalize()) != metadata.sha256.to_ascii_lowercase() {
            return Err(io::Error::other("内置资源校验和或长度不一致"));
        }
        output.sync_all()?;
        drop(output);
        if !validate(&temporary) { return Err(io::Error::other("内置资源格式无效")); }
        if destination.exists() { fs::remove_file(destination)?; }
        fs::rename(&temporary, destination)
    })();
    if result.is_err() { let _ = fs::remove_file(temporary); }
    result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fixture(data: &[u8], file: &str) -> (Vec<u8>, PackedResource) {
        let mut bytes = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut bytes, 4096, 4, 20);
            encoder.write_all(data).unwrap();
        }
        let metadata = PackedResource {
            file: file.into(), sha256: format!("{:x}", Sha256::digest(&bytes)), size: bytes.len() as u64,
            unpacked_sha256: format!("{:x}", Sha256::digest(data)), unpacked_size: data.len() as u64,
        };
        (bytes, metadata)
    }

    #[test]
    fn verified_stream_is_identical_and_failed_unpack_preserves_existing_file() {
        let root = std::env::temp_dir().join(format!("billow-packed-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let dest = root.join("core");
        let data = vec![42; 140_000];
        let (bytes, metadata) = fixture(&data, "core.br");
        unpack(bytes.as_slice(), &dest, &metadata, |_| true).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), data);
        for bad in [
            PackedResource { unpacked_size: 100, ..metadata.clone() },
            PackedResource { sha256: "0".repeat(64), ..metadata.clone() },
            PackedResource { unpacked_sha256: "0".repeat(64), ..metadata.clone() },
            PackedResource { size: metadata.size + 1, ..metadata.clone() },
        ] {
            assert!(unpack(bytes.as_slice(), &dest, &bad, |_| true).is_err());
            assert_eq!(fs::read(&dest).unwrap(), data);
        }
        assert!(unpack(&bytes[..bytes.len() / 2], &dest, &metadata, |_| true).is_err());
        assert!(unpack(bytes.as_slice(), &dest, &metadata, |_| false).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1, "failed temporary files are removed");
        fs::remove_dir_all(root).unwrap();
    }
}
