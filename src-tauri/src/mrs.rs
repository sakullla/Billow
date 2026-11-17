//! Read-only decoder for Mihomo's binary rule sets (`format: mrs`, MRSv1).
//!
//! An MRS file is a zstd stream holding `MRS\x01`, a behavior byte (0 domain,
//! 1 ipcidr), the rule count and a reserved block, then either a succinct domain
//! trie or a list of IP ranges. The output matches `mihomo convert-ruleset
//! <behavior> mrs`: domain patterns sorted with `x` + `.x` merged into `+.x`, and
//! IP ranges written back as CIDR prefixes.

use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

const MAGIC: [u8; 4] = *b"MRS\x01";
/// Hard cap on decompressed bytes so a crafted file cannot exhaust memory.
const MAX_DECODED: u64 = 128 * 1024 * 1024;
/// Upper bound on emitted entries; real sets stay far below this.
const MAX_ENTRIES: usize = 4_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrsRules {
    /// `domain` or `ipcidr`.
    pub behavior: &'static str,
    pub rules: Vec<String>,
}

/// Decode an MRS file into rule lines; `Err` explains why the file is unreadable.
pub fn decode(compressed: &[u8]) -> Result<MrsRules, String> {
    let body = decompress(compressed)?;
    let mut input = Cursor { data: &body, at: 0 };
    if input.take(4)? != MAGIC {
        return Err("不是有效的 MRS 文件".to_string());
    }
    let behavior = input.u8()?;
    let _count = input.i64()?;
    let extra = input.i64()?;
    if extra < 0 {
        return Err("MRS 文件头已损坏".to_string());
    }
    input.take(extra as usize)?;
    match behavior {
        0 => Ok(MrsRules { behavior: "domain", rules: domain_rules(&mut input)? }),
        1 => Ok(MrsRules { behavior: "ipcidr", rules: ipcidr_rules(&mut input)? }),
        other => Err(format!("不支持的 MRS 规则类型（{other}）")),
    }
}

fn decompress(compressed: &[u8]) -> Result<Vec<u8>, String> {
    use ruzstd::decoding::StreamingDecoder;
    let mut input = compressed;
    let mut out = Vec::new();
    // A zstd stream may consist of several frames; decode them back to back.
    while !input.is_empty() {
        let decoder = match StreamingDecoder::new(&mut input) {
            Ok(decoder) => decoder,
            Err(_) if !out.is_empty() => break,
            Err(err) => return Err(format!("MRS 解压失败：{err}")),
        };
        let budget = MAX_DECODED.saturating_sub(out.len() as u64);
        decoder
            .take(budget + 1)
            .read_to_end(&mut out)
            .map_err(|err| format!("MRS 解压失败：{err}"))?;
        if out.len() as u64 > MAX_DECODED {
            return Err("MRS 规则集解压后过大，已跳过预览".to_string());
        }
    }
    Ok(out)
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(len).filter(|&end| end <= self.data.len());
        let Some(end) = end else { return Err("MRS 文件不完整".to_string()) };
        let slice = &self.data[self.at..end];
        self.at = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
    /// A positive length prefix whose payload of `unit`-byte items must fit in the rest.
    fn len(&mut self, unit: usize) -> Result<usize, String> {
        let len = self.i64()?;
        let rest = self.data.len() - self.at;
        if len < 1 || (len as u128) * (unit as u128) > rest as u128 {
            return Err("MRS 数据长度无效".to_string());
        }
        Ok(len as usize)
    }
    fn words(&mut self) -> Result<Words<'a>, String> {
        let len = self.len(8)?;
        Ok(Words(self.take(len * 8)?))
    }
}

/// Borrow the decompressed bitmap instead of allocating a second copy.
struct Words<'a>(&'a [u8]);

impl Words<'_> {
    fn len(&self) -> usize { self.0.len() / 8 }

    fn get(&self, index: usize) -> Option<u64> {
        self.0.chunks_exact(8).nth(index)
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("8 bytes")))
    }
}

fn bit(words: &Words, index: usize) -> Result<bool, String> {
    words
        .get(index >> 6)
        .map(|word| word & (1 << (index & 63)) != 0)
        .ok_or_else(|| "MRS 域名树已损坏".to_string())
}

/// Walk the succinct trie (LOUDS-style label bitmap) and list every stored key.
fn domain_rules(input: &mut Cursor) -> Result<Vec<String>, String> {
    if input.u8()? != 1 {
        return Err("不支持的 MRS 域名集版本".to_string());
    }
    let leaves = input.words()?;
    let bitmap = input.words()?;
    let labels_len = input.len(1)?;
    let labels = input.take(labels_len)?;
    let corrupt = || "MRS 域名树已损坏".to_string();

    // select(i): position of the i-th set bit, the end of node i's label run.
    // The decoded-byte cap keeps bit positions below u32::MAX. Visit set bits
    // directly rather than testing every bit and storing pointer-sized indices.
    let mut ones: Vec<u32> = Vec::new();
    for (word_index, bytes) in bitmap.0.chunks_exact(8).enumerate() {
        let mut word = u64::from_be_bytes(bytes.try_into().expect("8 bytes"));
        while word != 0 {
            ones.push((word_index * 64 + word.trailing_zeros() as usize) as u32);
            word &= word - 1;
        }
    }

    let child_of = |node: usize, wanted: u8| -> Result<Option<usize>, String> {
        let mut index = if node == 0 { 0 } else { *ones.get(node - 1).ok_or_else(corrupt)? as usize + 1 };
        while !bit(&bitmap, index)? {
            let offset = index.checked_sub(node).ok_or_else(corrupt)?;
            let label = *labels.get(offset).ok_or_else(corrupt)?;
            if label == wanted { return Ok(Some(offset + 1)); }
            index += 1;
        }
        Ok(None)
    };
    let mut keys: Vec<String> = Vec::new();
    let mut terminals = 0;
    let mut emit = |key: &[u8], node: usize, ancestors: &[(usize, usize)]| -> Result<(), String> {
        terminals += 1;
        if terminals > MAX_ENTRIES {
            return Err("MRS 规则集条目过多，已跳过预览".to_string());
        }
        if key.is_empty() { return Ok(()); }
        // The suffix-only path for x is reverse(x) + ".+". Its exact-domain
        // terminal is two ancestors up, so merge the pair directly in the trie.
        // This avoids creating, sorting and then discarding a second rule for x.
        if key.ends_with(b".+") && ancestors.len() >= 3
            && bit(&leaves, ancestors[ancestors.len() - 3].0)? {
            return Ok(());
        }
        let mut paired = false;
        if let Some(dot) = child_of(node, b'.')? {
            if let Some(suffix) = child_of(dot, b'+')? {
                paired = bit(&leaves, suffix)?;
            }
        }
        let key = String::from_utf8_lossy(key);
        let key = key.strip_suffix('+').unwrap_or(&key);
        let mut rule = String::with_capacity(key.len() + if paired { 2 } else { 0 });
        if paired { rule.push_str("+."); }
        rule.extend(key.chars().rev());
        keys.push(rule);
        Ok(())
    };

    let mut key: Vec<u8> = Vec::new();
    // (node id, next label-bitmap index to look at)
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    if bit(&leaves, 0)? {
        emit(&key, 0, &stack)?;
    }
    let step_limit = bitmap.len() * 64 + labels.len() + 1;
    let mut steps = 0usize;
    while let Some(&(node, index)) = stack.last() {
        steps += 1;
        if steps > step_limit || stack.len() > 4096 {
            return Err(corrupt());
        }
        if bit(&bitmap, index)? {
            stack.pop();
            key.pop();
            continue;
        }
        if let Some(top) = stack.last_mut() {
            top.1 += 1;
        }
        let label = *index.checked_sub(node).and_then(|offset| labels.get(offset)).ok_or_else(corrupt)?;
        let child = index - node + 1;
        let child_at = *ones.get(child - 1).ok_or_else(corrupt)? as usize + 1;
        key.push(label);
        stack.push((child, child_at));
        if bit(&leaves, child)? {
            emit(&key, child, &stack)?;
        }
    }

    keys.sort_unstable();
    Ok(keys)
}

fn ipcidr_rules(input: &mut Cursor) -> Result<Vec<String>, String> {
    if input.u8()? != 1 {
        return Err("不支持的 MRS IP 集版本".to_string());
    }
    let count = input.len(32)?;
    let mut rules = Vec::new();
    for _ in 0..count {
        let from: [u8; 16] = input.take(16)?.try_into().expect("16 bytes");
        let to: [u8; 16] = input.take(16)?.try_into().expect("16 bytes");
        let (from, to) = (Ipv6Addr::from(from), Ipv6Addr::from(to));
        match (from.to_ipv4_mapped(), to.to_ipv4_mapped()) {
            (Some(from), Some(to)) => {
                let (from, to) = (u32::from(from) as u128, u32::from(to) as u128);
                push_prefixes(&mut rules, from, to, 32, |value| Ipv4Addr::from(value as u32).to_string())?;
            }
            _ => {
                let (from, to) = (u128::from(from), u128::from(to));
                push_prefixes(&mut rules, from, to, 128, |value| Ipv6Addr::from(value).to_string())?;
            }
        }
    }
    Ok(rules)
}

/// Split an inclusive range into the fewest aligned prefixes, in address order.
fn push_prefixes(out: &mut Vec<String>, mut from: u128, to: u128, bits: u32, show: impl Fn(u128) -> String) -> Result<(), String> {
    if from > to {
        return Err("MRS IP 范围已损坏".to_string());
    }
    loop {
        // Largest block aligned at `from` that still ends within the range.
        let mut size = if from == 0 { bits } else { from.trailing_zeros().min(bits) };
        while size > 0 && block_end(from, size).is_none_or(|end| end > to) {
            size -= 1;
        }
        if out.len() >= MAX_ENTRIES {
            return Err("MRS 规则集条目过多，已跳过预览".to_string());
        }
        out.push(format!("{}/{}", show(from), bits - size));
        match block_end(from, size).and_then(|end| end.checked_add(1)) {
            Some(next) if next <= to => from = next,
            _ => return Ok(()),
        }
    }
}

fn block_end(from: u128, size: u32) -> Option<u128> {
    if size >= 128 {
        return if from == 0 { Some(u128::MAX) } else { None };
    }
    from.checked_add((1u128 << size) - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced by `mihomo convert-ruleset` from Mihomo v1.19.34 (the bundled kernel):
    // domain: +.google.com, example.org, .only-sub.net, *.wild.io, a.b.c.d.e
    const DOMAIN_MRS: &[u8] = include_bytes!("../testdata/domain.mrs");
    // ipcidr: 1.0.0.0/24, 1.0.1.0/24, 10.0.0.0/8, 192.168.1.0/30, 2001:db8::/32
    const IP_MRS: &[u8] = include_bytes!("../testdata/ipcidr.mrs");

    #[test]
    fn domain_sets_dump_like_mihomo() {
        let decoded = decode(DOMAIN_MRS).unwrap();
        assert_eq!(decoded.behavior, "domain");
        // Identical to `mihomo convert-ruleset domain mrs domain.mrs out.txt`.
        assert_eq!(decoded.rules, ["*.wild.io", "+.google.com", ".only-sub.net", "a.b.c.d.e", "example.org"]);
    }

    #[test]
    fn ip_sets_dump_as_merged_prefixes() {
        let decoded = decode(IP_MRS).unwrap();
        assert_eq!(decoded.behavior, "ipcidr");
        assert_eq!(decoded.rules, ["1.0.0.0/23", "10.0.0.0/8", "192.168.1.0/30", "2001:db8::/32"]);
    }

    #[test]
    fn trie_pairing_preserves_wildcards_nested_suffixes_and_unicode() {
        // Exported by the bundled Mihomo v1.19.34 from the same MRS fixture.
        let decoded = decode(include_bytes!("../testdata/domain-complex.mrs")).unwrap();
        assert_eq!(decoded.rules, [
            "*.nested.wild.example", "*.wild.example", "+.bücher.example", "+.exact.example",
            "+.paired.example", "+.parent.example", ".deep.example", ".only.example",
            "child.parent.example", "leaf.deep.example", "plain.example", "中文.example",
        ]);
    }

    #[test]
    fn ranges_split_into_aligned_prefixes() {
        let mut out = Vec::new();
        push_prefixes(&mut out, 1, 6, 32, |value| Ipv4Addr::from(value as u32).to_string()).unwrap();
        assert_eq!(out, ["0.0.0.1/32", "0.0.0.2/31", "0.0.0.4/31", "0.0.0.6/32"]);
        let mut all = Vec::new();
        push_prefixes(&mut all, 0, u128::MAX, 128, |value| Ipv6Addr::from(value).to_string()).unwrap();
        assert_eq!(all, ["::/0"]);
        let mut v4 = Vec::new();
        push_prefixes(&mut v4, 0, u32::MAX as u128, 32, |value| Ipv4Addr::from(value as u32).to_string()).unwrap();
        assert_eq!(v4, ["0.0.0.0/0"]);
    }

    #[test]
    fn damaged_files_report_instead_of_panicking() {
        assert!(decode(b"not zstd").is_err());
        // Every truncation of a valid file is rejected or decoded, never a panic.
        for cut in 0..DOMAIN_MRS.len() {
            let _ = decode(&DOMAIN_MRS[..cut]);
        }
        for cut in 0..IP_MRS.len() {
            let _ = decode(&IP_MRS[..cut]);
        }
    }
}

