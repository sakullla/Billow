use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

const FILES: [&str; 4] = ["ASN.mmdb", "Country.mmdb", "GeoIP.dat", "GeoSite.dat"];

fn usable_cache(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else { return false; };
    if !meta.is_file() || meta.len() == 0 { return false; }
    if !matches!(path.extension().and_then(|ext| ext.to_str()), Some("mmdb" | "metadb" | "db")) { return true; }
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

/// Desktop installers carry the same GEO snapshot as Android, as ordinary resources.
pub fn seed_directory(resources: &Path, home: &Path) -> Result<(), String> {
    fs::create_dir_all(home).map_err(|error| format!("GEO 数据目录不可用：{error}"))?;
    for name in FILES {
        if usable_cache(&home.join(name)) { continue; }
        // Mihomo also recognises lowercase files and the historic MMDB filenames.
        let aliases: &[&str] = match name {
            "Country.mmdb" => &["country.mmdb", "geoip.metadb", "GeoIP.metadb", "geoip.db"],
            "ASN.mmdb" => &["asn.mmdb"],
            "GeoIP.dat" => &["geoip.dat"],
            "GeoSite.dat" => &["geosite.dat"],
            _ => &[],
        };
        if aliases.iter().any(|alias| usable_cache(&home.join(alias))) {
            // A broken canonical file must not shadow a valid user-updated alias.
            let destination = home.join(name);
            if destination.exists() {
                fs::remove_file(&destination).map_err(|error| format!("无法清理损坏的 GEO 数据：{name}：{error}"))?;
            }
            continue;
        }
        let source = resources.join(name);
        if !usable_cache(&source) { return Err(format!("安装包中的 GEO 数据缺失或损坏：{name}")); }
        let temporary = home.join(format!(".{name}.seed"));
        let copied = (|| -> io::Result<()> {
            let mut input = File::open(&source)?;
            let mut output = File::create(&temporary)?;
            io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            drop(output);
            let destination = home.join(name);
            if destination.exists() { fs::remove_file(&destination)?; }
            fs::rename(&temporary, destination)
        })();
        if copied.is_err() { let _ = fs::remove_file(temporary); }
        copied.map_err(|error| format!("内置 GEO 数据初始化失败：{name}：{error}"))?;
    }
    Ok(())
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

    #[test]
    fn desktop_seeds_offline_repairs_bad_files_and_preserves_user_updates_and_aliases() {
        let root = std::env::temp_dir().join(format!("billow-desktop-geo-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let resources = root.join("package");
        let home = root.join("home");
        fs::create_dir_all(&resources).unwrap();
        fs::create_dir_all(&home).unwrap();
        for name in FILES {
            let mut content = name.as_bytes().to_vec();
            if name.ends_with(".mmdb") { content.extend_from_slice(b"\xab\xcd\xefMaxMind.commetadata"); }
            fs::write(resources.join(name), content).unwrap();
        }
        fs::write(home.join("ASN.mmdb"), b"truncated").unwrap();
        fs::write(home.join("GeoIP.dat"), b"").unwrap();
        fs::write(home.join("geosite.dat"), b"user-updated").unwrap();
        fs::write(home.join("Country.mmdb"), b"broken-mmdb").unwrap();
        fs::write(home.join("geoip.metadb"), b"user-mmdb\xab\xcd\xefMaxMind.commetadata").unwrap();
        seed_directory(&resources, &home).unwrap();
        assert!(usable_cache(&home.join("ASN.mmdb")));
        assert_eq!(fs::read(home.join("GeoIP.dat")).unwrap(), b"GeoIP.dat");
        assert_eq!(fs::read(home.join("geosite.dat")).unwrap(), b"user-updated");
        assert!(!home.join("Country.mmdb").exists());
        fs::remove_dir_all(&resources).unwrap();
        seed_directory(&resources, &home).unwrap();
        fs::remove_file(home.join("ASN.mmdb")).unwrap();
        assert!(seed_directory(&resources, &home).unwrap_err().contains("ASN.mmdb"));
        fs::remove_dir_all(root).unwrap();
    }
}
