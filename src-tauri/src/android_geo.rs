use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

const FILES: [&str; 4] = ["ASN.mmdb", "Country.mmdb", "GeoIP.dat", "GeoSite.dat"];

fn usable_cache(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else { return false; };
    if !meta.is_file() || meta.len() == 0 { return false; }
    if path.extension().is_none_or(|ext| ext != "mmdb") { return true; }
    // Interrupted upstream downloads can leave nonempty MMDB files. Their
    // required metadata footer is missing; do not mistake them for user updates.
    let read_footer = || -> io::Result<bool> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(meta.len().saturating_sub(128 * 1024)))?;
        let mut footer = Vec::new();
        file.take(128 * 1024).read_to_end(&mut footer)?;
        let marker = b"\xab\xcd\xefMaxMind.com";
        Ok(footer.windows(marker.len()).any(|part| part == marker))
    };
    read_footer().unwrap_or(false)
}

/// Stream the packaged defaults to the writable kernel home once. Keep user updates.
pub fn seed(apk: &Path, home: &Path) -> Result<(), String> {
    let missing: Vec<_> = FILES.into_iter().filter(|name| !usable_cache(&home.join(name))).collect();
    if missing.is_empty() { return Ok(()); }
    let install = || -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(home)?;
        let mut archive = zip::ZipArchive::new(File::open(apk)?)?;
        for name in missing {
            let mut source = archive.by_name(&format!("assets/billow-geo/{name}"))?;
            if source.size() == 0 { return Err(format!("{name} 数据为空").into()); }
            let temporary = home.join(format!(".{name}.seed"));
            let copied = (|| -> io::Result<()> {
                let mut output = File::create(&temporary)?;
                io::copy(&mut source, &mut output)?;
                output.sync_all()?;
                drop(output);
                // A previous failed download may have left an empty destination.
                let destination = home.join(name);
                if destination.exists() { fs::remove_file(&destination)?; }
                fs::rename(&temporary, destination)
            })();
            if copied.is_err() { let _ = fs::remove_file(temporary); }
            copied?;
        }
        Ok(())
    };
    install().map_err(|error| format!("内置 GEO 数据初始化失败：{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn first_launch_seeds_without_network_and_preserves_updated_files() {
        let root = std::env::temp_dir().join(format!("billow-geo-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&root).unwrap();
        let apk = root.join("app.apk");
        let mut writer = zip::ZipWriter::new(File::create(&apk).unwrap());
        for name in FILES {
            writer.start_file(format!("assets/billow-geo/{name}"), zip::write::SimpleFileOptions::default()).unwrap();
            writer.write_all(name.as_bytes()).unwrap();
            if name.ends_with(".mmdb") { writer.write_all(b"\xab\xcd\xefMaxMind.commetadata").unwrap(); }
        }
        writer.finish().unwrap();
        let home = root.join("profiles");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("ASN.mmdb"), b"").unwrap();
        fs::write(home.join("Country.mmdb"), b"interrupted-nonempty-download").unwrap();
        fs::write(home.join("GeoSite.dat"), b"user-updated").unwrap();
        seed(&apk, &home).unwrap();
        assert!(usable_cache(&home.join("ASN.mmdb")));
        assert!(fs::read(home.join("Country.mmdb")).unwrap().starts_with(b"Country.mmdb"));
        assert_eq!(fs::read(home.join("GeoSite.dat")).unwrap(), b"user-updated");
        fs::remove_file(&apk).unwrap();
        seed(&apk, &home).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_package_fails_before_starting_the_kernel() {
        let root = std::env::temp_dir().join(format!("billow-missing-geo-{}", std::process::id()));
        assert!(seed(&root.join("missing.apk"), &root).unwrap_err().contains("GEO"));
        let _ = fs::remove_dir_all(root);
    }
}
