//! A disk-backed index for large classical rule providers. Exact and suffix
//! entries are pure domain checks. Their ordinals let the rule engine keep
//! the ordering of interleaved rules that may trigger DNS resolution.

use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::{trim_rule_field, RuleFormat};
use crate::geodata::read_file_at;

const BUCKET_BITS: u32 = 5;
const MAX_SORT_ROWS: u64 = 240_000;
const BLOCK_ROWS: usize = 170;
const MAX_LINE: u64 = 64 * 1024;
type Row = [u8; 24];

#[derive(Debug)]
pub(crate) struct IndexedDomains {
    rows: File,
    names: File,
    count: u64,
    block_keys: Vec<[u8; 8]>,
    _directory: IndexDirectory,
}

#[derive(Debug)]
struct IndexDirectory(PathBuf);

impl IndexDirectory {
    fn create() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("billow-rules-{}", uuid::Uuid::new_v4()));
        let mut directory = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for IndexDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn key(suffix: bool, domain: &str) -> [u8; 8] {
    let mut hasher = DefaultHasher::new();
    suffix.hash(&mut hasher);
    domain.hash(&mut hasher);
    hasher.finish().to_be_bytes()
}

pub(crate) struct IndexedFile {
    pub domains: Arc<IndexedDomains>,
    pub other_rules: Vec<String>,
    pub other_positions: Vec<u64>,
    pub count: usize,
}

impl IndexedDomains {
    /// Find the earliest domain rule. The hash only locates candidates; each
    /// candidate is checked against the original normalized name and type.
    pub fn first_match(&self, host: &str) -> io::Result<Option<u64>> {
        let mut first = self.lookup(false, host)?;
        if first == Some(0) {
            return Ok(first);
        }
        for suffix in
            std::iter::once(host).chain(host.match_indices('.').map(|(i, _)| &host[i + 1..]))
        {
            if let Some(candidate) = self.lookup(true, suffix)? {
                first = Some(first.map_or(candidate, |previous| previous.min(candidate)));
                if candidate == 0 {
                    break;
                }
            }
        }
        Ok(first)
    }

    fn lookup(&self, suffix: bool, domain: &str) -> io::Result<Option<u64>> {
        let wanted = key(suffix, domain);
        let start = self
            .block_keys
            .partition_point(|head| *head < wanted)
            .saturating_sub(1);
        let mut page = [0; BLOCK_ROWS * size_of::<Row>()];
        for block in start..self.block_keys.len() {
            if self.block_keys[block] > wanted {
                break;
            }
            let row_start = block as u64 * BLOCK_ROWS as u64;
            let size = (self.count - row_start).min(BLOCK_ROWS as u64) as usize * size_of::<Row>();
            read_file_at(
                &self.rows,
                &mut page[..size],
                row_start * size_of::<Row>() as u64,
            )?;
            let rows = page[..size].as_chunks::<24>().0;
            let start = rows.partition_point(|row| row[..8] < wanted[..]);
            for row in &rows[start..] {
                if row[..8] != wanted {
                    break;
                }
                let offset = u64::from_be_bytes(row[16..24].try_into().unwrap());
                let mut header = [0; 5];
                read_file_at(&self.names, &mut header, offset)?;
                let size = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
                if header[0] == u8::from(suffix) && size == domain.len() {
                    let mut short = [0; 256];
                    let mut long;
                    let bytes = if size <= short.len() {
                        &mut short[..size]
                    } else {
                        long = vec![0; size];
                        &mut long
                    };
                    read_file_at(&self.names, bytes, offset + 5)?;
                    if bytes == domain.as_bytes() {
                        return Ok(Some(u64::from_be_bytes(row[8..16].try_into().unwrap())));
                    }
                }
            }
        }
        Ok(None)
    }
}

fn buckets(directory: &Path, prefix: &str, bits: u32) -> io::Result<Vec<BufWriter<File>>> {
    (0..1 << bits)
        .map(|i| File::create(directory.join(format!("{prefix}-{i}"))).map(BufWriter::new))
        .collect()
}

fn bucket_number(hash: [u8; 8], used: u32, bits: u32) -> usize {
    ((u64::from_be_bytes(hash) >> (64 - used - bits)) & ((1 << bits) - 1)) as usize
}

struct SortedRows {
    writer: BufWriter<File>,
    block_keys: Vec<[u8; 8]>,
    count: u64,
}

impl SortedRows {
    fn write_row(&mut self, row: &Row) -> io::Result<()> {
        if self.count % BLOCK_ROWS as u64 == 0 {
            self.block_keys.push(row[..8].try_into().unwrap());
        }
        self.writer.write_all(row)?;
        self.count += 1;
        Ok(())
    }

    fn sort_bucket(&mut self, path: &Path, used: u32) -> io::Result<()> {
        let file = File::open(path)?;
        let len = file.metadata()?.len() / size_of::<Row>() as u64;
        let mut reader = BufReader::new(file);
        if len <= MAX_SORT_ROWS {
            let mut rows = Vec::with_capacity(len as usize);
            for _ in 0..len {
                let mut row = [0; size_of::<Row>()];
                reader.read_exact(&mut row)?;
                rows.push(row);
            }
            rows.sort_unstable();
            for row in &rows {
                self.write_row(row)?;
            }
        } else if used == 64 {
            // All rows now have the same hash. Partitioning preserved their
            // input order, so ordinals already sort inside this hash.
            for _ in 0..len {
                let mut row = [0; size_of::<Row>()];
                reader.read_exact(&mut row)?;
                self.write_row(&row)?;
            }
        } else {
            let remaining = (64 - used).min(BUCKET_BITS);
            let directory = path.parent().unwrap();
            let prefix = path.file_name().unwrap().to_str().unwrap();
            let mut children = buckets(directory, prefix, remaining)?;
            for _ in 0..len {
                let mut row = [0; size_of::<Row>()];
                reader.read_exact(&mut row)?;
                let bucket = bucket_number(row[..8].try_into().unwrap(), used, remaining);
                children[bucket].write_all(&row)?;
            }
            for mut child in children {
                child.flush()?;
            }
            for i in 0..1 << remaining {
                self.sort_bucket(&directory.join(format!("{prefix}-{i}")), used + remaining)?;
            }
        }
        drop(reader);
        fs::remove_file(path)
    }
}

/// Recognize the two ordinary target-less domain rules without allocating a
/// full Rule. Any extra fields go through the regular parser and validation.
fn domain_rule(line: &str) -> Option<(bool, &str)> {
    let (kind, name) = line.split_once(',')?;
    if name.contains(',') {
        return None;
    }
    let kind = trim_rule_field(kind);
    let name = trim_rule_field(name);
    if name.is_empty() {
        return None;
    }
    if kind.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
        Some((true, name))
    } else if kind.eq_ignore_ascii_case("DOMAIN") {
        Some((false, name))
    } else {
        None
    }
}

/// Stream text or YAML's common single block of plain rule strings. Complex
/// YAML uses the existing loader so tags, aliases and merges retain their
/// established behavior.
pub(crate) fn index_file(file: File, format: RuleFormat) -> io::Result<Option<IndexedFile>> {
    let directory = IndexDirectory::create()?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut writers = buckets(&directory.0, "bucket", BUCKET_BITS)?;
    let names_path = directory.0.join("names");
    let mut names = BufWriter::with_capacity(64 * 1024, File::create(&names_path)?);
    let mut name_offset = 0u64;
    let mut count = 0usize;
    let mut other_rules = Vec::new();
    let mut other_positions = Vec::new();
    let mut line = String::new();
    let mut normalized = String::new();
    let mut header = false;
    let mut indent = None;
    loop {
        line.clear();
        let read = reader.by_ref().take(MAX_LINE + 1).read_line(&mut line)?;
        if read == 0 {
            break;
        }
        if read as u64 > MAX_LINE {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let entry = if format == RuleFormat::Yaml {
            let whitespace = line.len() - line.trim_start_matches(' ').len();
            if !header {
                if whitespace != 0
                    || !matches!(
                        line.trim_end_matches(['\r', '\n', ' ']),
                        "payload:" | "rules:"
                    )
                {
                    return Ok(None);
                }
                header = true;
                continue;
            }
            if *indent.get_or_insert(whitespace) != whitespace {
                return Ok(None);
            }
            let Some(entry) = line[whitespace..]
                .trim_end_matches(['\r', '\n', ' '])
                .strip_prefix("- ")
            else {
                return Ok(None);
            };
            let entry = entry.trim_start_matches(' ');
            if !entry
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
                || (!entry.is_ascii()
                    && entry.chars().any(|ch| {
                        matches!(
                            ch,
                            '\u{0080}'
                                ..='\u{009f}'
                                    | '\u{2028}'
                                    | '\u{2029}'
                                    | '\u{feff}'
                                    | '\u{fffe}'
                                    | '\u{ffff}'
                        )
                    }))
                || entry.contains(['#', '\t', '[', ']', '{', '}', '\'', '"', '\r'])
                || entry.contains(": ")
                || entry.ends_with(':')
                || !entry.contains(',')
            {
                return Ok(None);
            }
            entry
        } else {
            if trimmed.starts_with("//") {
                continue;
            }
            trimmed
        };
        if let Some((suffix, domain)) = domain_rule(entry) {
            normalized.clear();
            normalized.push_str(domain);
            normalized.make_ascii_lowercase();
            let hash = key(suffix, &normalized);
            let mut row = [0; size_of::<Row>()];
            row[..8].copy_from_slice(&hash);
            row[8..16].copy_from_slice(&(count as u64).to_be_bytes());
            row[16..24].copy_from_slice(&name_offset.to_be_bytes());
            writers[bucket_number(hash, 0, BUCKET_BITS)].write_all(&row)?;
            names.write_all(&[u8::from(suffix)])?;
            names.write_all(&(normalized.len() as u32).to_be_bytes())?;
            names.write_all(normalized.as_bytes())?;
            name_offset += 5 + normalized.len() as u64;
        } else {
            other_positions.push(count as u64);
            other_rules.push(entry.to_string());
        }
        count += 1;
    }
    if name_offset == 0 {
        return Ok(None);
    }
    for mut writer in writers {
        writer.flush()?;
    }
    names.flush()?;
    drop(names);

    let index_path = directory.0.join("sorted");
    let mut rows = SortedRows {
        writer: BufWriter::with_capacity(64 * 1024, File::create(&index_path)?),
        block_keys: Vec::new(),
        count: 0,
    };
    for i in 0..1 << BUCKET_BITS {
        rows.sort_bucket(&directory.0.join(format!("bucket-{i}")), BUCKET_BITS)?;
    }
    rows.writer.flush()?;
    drop(rows.writer);
    Ok(Some(IndexedFile {
        domains: Arc::new(IndexedDomains {
            rows: File::open(index_path)?,
            names: File::open(names_path)?,
            count: rows.count,
            block_keys: rows.block_keys,
            _directory: directory,
        }),
        other_rules,
        other_positions,
        count,
    }))
}
