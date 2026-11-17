//! 覆写 (profile override) engine.
//!
//! Two forms share one text field, like Clash Party:
//!
//! * **YAML** – deep-merged onto the profile. Mappings merge recursively, other
//!   values replace. Key modifiers: `key!` replaces the whole value instead of
//!   merging, `+key` prepends a list, `key+` appends a list, and `<key>` quotes
//!   a key that itself starts or ends with `+` (e.g. `<+.google.cn>`). The
//!   Clash Verge keys `prepend-rules` / `append-proxies` / … are accepted too.
//! * **JavaScript** – a script defining `function main(config, profileName)`
//!   that returns the modified config. It runs in an isolated QuickJS context
//!   with memory and time limits; `console.log` output is collected.

use rquickjs::{CatchResultExt, CaughtError, Context, Function, Object, Promise, Runtime, Value as JsValue};
use serde_yaml::{Mapping, Value};
use std::time::{Duration, Instant};

#[cfg(not(test))]
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const SCRIPT_TIMEOUT: Duration = Duration::from_millis(500);
const SCRIPT_MEMORY: usize = 256 * 1024 * 1024;
const SCRIPT_STACK: usize = 1024 * 1024;
const MAX_LOGS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideKind {
    Yaml,
    Script,
}

/// Result of applying an override: the merged config and anything the script logged.
#[derive(Debug, Default)]
pub struct Applied {
    pub logs: Vec<String>,
}

/// A script is recognised by a top-level `main` definition at the start of a line.
/// Inside YAML such text could only appear in an indented block scalar.
pub fn kind_of(text: &str) -> OverrideKind {
    for line in text.lines() {
        let line = line.trim_end();
        let is_main = |rest: &str| {
            let rest = rest.trim_start();
            rest.starts_with("main") && rest[4..].trim_start().starts_with(['(', '='])
        };
        if let Some(rest) = line.strip_prefix("function") {
            if rest.starts_with(char::is_whitespace) && is_main(rest) {
                return OverrideKind::Script;
            }
        }
        if let Some(rest) = line.strip_prefix("async function") {
            if is_main(rest) {
                return OverrideKind::Script;
            }
        }
        for decl in ["const ", "let ", "var "] {
            if let Some(rest) = line.strip_prefix(decl) {
                if is_main(rest) {
                    return OverrideKind::Script;
                }
            }
        }
    }
    OverrideKind::Yaml
}

/// Apply `text` onto `base`. Errors are user-facing Chinese messages.
pub fn apply(base: &mut Value, text: &str, profile_name: &str, parse: impl Fn(&str) -> Result<Value, serde_yaml::Error>) -> Result<Applied, String> {
    if text.trim().is_empty() {
        return Ok(Applied::default());
    }
    match kind_of(text) {
        OverrideKind::Yaml => {
            let overlay = parse(text).map_err(|error| yaml_error(&error))?;
            match overlay {
                Value::Null => {}
                Value::Mapping(map) => merge_mapping(base, &map),
                _ => return Err("YAML 覆写需要是键值对，例如 mixed-port: 7890".to_string()),
            }
            Ok(Applied::default())
        }
        OverrideKind::Script => run_script(base, text, profile_name),
    }
}

fn yaml_error(error: &serde_yaml::Error) -> String {
    match error.location() {
        Some(location) => format!("YAML 第 {} 行第 {} 列有误：{}", location.line(), location.column(), strip_location(&error.to_string())),
        None => format!("YAML 有误：{error}"),
    }
}

fn strip_location(message: &str) -> String {
    match message.find(" at line ") {
        Some(index) => message[..index].to_string(),
        None => message.to_string(),
    }
}

// ── YAML merge ──

enum Op {
    Merge,
    Replace,
    Prepend,
    Append,
}

/// `<name>` is a quoted key; modifiers outside the brackets still apply.
fn unwrap_key(name: &str) -> &str {
    if name.len() >= 2 && name.starts_with('<') && name.ends_with('>') {
        &name[1..name.len() - 1]
    } else {
        name
    }
}

fn parse_key(raw: &str, value: &Value) -> (String, Op) {
    if let Some(name) = raw.strip_suffix('!') {
        return (unwrap_key(name).to_string(), Op::Replace);
    }
    if value.is_sequence() {
        if let Some(name) = raw.strip_prefix('+') {
            return (unwrap_key(name).to_string(), Op::Prepend);
        }
        if let Some(name) = raw.strip_suffix('+') {
            return (unwrap_key(name).to_string(), Op::Append);
        }
    }
    let op = if value.is_mapping() { Op::Merge } else { Op::Replace };
    (unwrap_key(raw).to_string(), op)
}

/// Clash Verge style list keys, only meaningful at the top level.
fn verge_key(raw: &str) -> Option<(&'static str, Op)> {
    Some(match raw {
        "prepend-rules" => ("rules", Op::Prepend),
        "append-rules" => ("rules", Op::Append),
        "prepend-proxies" => ("proxies", Op::Prepend),
        "append-proxies" => ("proxies", Op::Append),
        "prepend-proxy-groups" => ("proxy-groups", Op::Prepend),
        "append-proxy-groups" => ("proxy-groups", Op::Append),
        _ => return None,
    })
}

fn merge_mapping(base: &mut Value, overlay: &Mapping) {
    merge_level(base, overlay, true);
}

fn merge_level(base: &mut Value, overlay: &Mapping, top: bool) {
    if !base.is_mapping() {
        *base = Value::Mapping(Mapping::new());
    }
    for (key, value) in overlay {
        let Some(raw) = key.as_str() else {
            insert(base, key.clone(), value.clone());
            continue;
        };
        let (name, op) = match verge_key(raw).filter(|_| top && value.is_sequence()) {
            Some((name, op)) => (name.to_string(), op),
            None => parse_key(raw, value),
        };
        let key = Value::String(name);
        let map = base.as_mapping_mut().expect("base is a mapping");
        match op {
            Op::Replace => {
                map.insert(key, value.clone());
            }
            Op::Merge => {
                let Some(over) = value.as_mapping() else {
                    map.insert(key, value.clone());
                    continue;
                };
                let slot = map.entry(key).or_insert_with(|| Value::Mapping(Mapping::new()));
                merge_level(slot, over, false);
            }
            Op::Prepend | Op::Append => {
                let items = value.as_sequence().cloned().unwrap_or_default();
                let slot = map.entry(key).or_insert(Value::Null);
                let existing = match std::mem::take(slot) {
                    Value::Sequence(list) => list,
                    _ => Vec::new(),
                };
                *slot = Value::Sequence(if matches!(op, Op::Prepend) {
                    items.into_iter().chain(existing).collect()
                } else {
                    existing.into_iter().chain(items).collect()
                });
            }
        }
    }
}

fn insert(base: &mut Value, key: Value, value: Value) {
    if let Some(map) = base.as_mapping_mut() {
        map.insert(key, value);
    }
}

// ── JavaScript ──

const PRELUDE: &str = r#"
(() => {
  const logs = [];
  const fmt = (v) => {
    if (typeof v === 'string') return v;
    try { return JSON.stringify(v); } catch (_) { return String(v); }
  };
  const push = (level) => (...args) => {
    if (logs.length < 200) logs.push((level ? level + ' ' : '') + args.map(fmt).join(' '));
  };
  globalThis.console = { log: push(''), info: push(''), debug: push(''), warn: push('[warn]'), error: push('[error]') };
  globalThis.__billowLogs = logs;
})();
"#;

fn run_script(base: &mut Value, source: &str, profile_name: &str) -> Result<Applied, String> {
    let input = serde_json::to_string(&*base).map_err(|_| "配置包含脚本无法读取的值（例如非字符串键）".to_string())?;
    let runtime = Runtime::new().map_err(|error| format!("脚本引擎启动失败：{error}"))?;
    runtime.set_memory_limit(SCRIPT_MEMORY);
    runtime.set_max_stack_size(SCRIPT_STACK);
    let started = Instant::now();
    runtime.set_interrupt_handler(Some(Box::new(move || started.elapsed() > SCRIPT_TIMEOUT)));
    let context = Context::full(&runtime).map_err(|error| format!("脚本引擎启动失败：{error}"))?;
    let timed_out = || started.elapsed() > SCRIPT_TIMEOUT;

    context.with(|ctx| {
        let describe = |error: CaughtError| {
            if timed_out() {
                return "脚本运行超时，已中止（可能存在死循环）".to_string();
            }
            describe_error(error)
        };
        ctx.eval::<(), _>(PRELUDE).catch(&ctx).map_err(describe)?;
        ctx.eval::<(), _>(source).catch(&ctx).map_err(|error| format!("脚本有误：{}", describe(error)))?;
        let main: Function = ctx
            .globals()
            .get::<_, JsValue>("main")
            .ok()
            .and_then(|value| value.into_function())
            .ok_or_else(|| "脚本需要定义 function main(config) 并返回修改后的配置".to_string())?;
        let config = ctx.json_parse(input).catch(&ctx).map_err(describe)?;
        let mut result: JsValue = main
            .call((config.clone(), profile_name))
            .catch(&ctx)
            .map_err(|error| format!("main 运行出错：{}", describe(error)))?;
        if let Some(promise) = result.as_promise().cloned() {
            result = drive(&promise).catch(&ctx).map_err(|error| format!("main 运行出错：{}", describe(error)))?;
        }
        if result.is_undefined() {
            // `main` mutated its argument in place and forgot to return it.
            result = config;
        }
        if !result.is_object() || result.is_array() {
            return Err("main 需要返回配置对象".to_string());
        }
        let json = ctx
            .json_stringify(result)
            .catch(&ctx)
            .map_err(describe)?
            .map(|text| text.to_string())
            .transpose()
            .map_err(|error| format!("脚本结果无法读取：{error}"))?
            .ok_or_else(|| "main 需要返回配置对象".to_string())?;
        let value: Value = serde_json::from_str(&json).map_err(|error| format!("脚本结果无法读取：{error}"))?;
        if !value.as_mapping().is_some_and(|map| !map.is_empty()) {
            return Err("main 返回了空配置".to_string());
        }
        *base = value;
        let logs = ctx
            .globals()
            .get::<_, Vec<String>>("__billowLogs")
            .unwrap_or_default()
            .into_iter()
            .take(MAX_LOGS)
            .collect();
        Ok(Applied { logs })
    })
}

fn drive<'js>(promise: &Promise<'js>) -> rquickjs::Result<JsValue<'js>> {
    match promise.finish::<JsValue>() {
        Err(rquickjs::Error::WouldBlock) => Err(rquickjs::Error::new_from_js_message(
            "Promise",
            "value",
            "main 返回的 Promise 没有完成（脚本中不能等待网络或定时器）",
        )),
        other => other,
    }
}

fn describe_error(error: CaughtError) -> String {
    match error {
        CaughtError::Exception(exception) => {
            let message = exception.message().unwrap_or_else(|| "未知错误".to_string());
            match exception.stack().as_deref().and_then(script_line) {
                Some(line) => format!("{message}（第 {line} 行）"),
                None => message,
            }
        }
        CaughtError::Value(value) => value
            .as_string()
            .and_then(|text| text.to_string().ok())
            .or_else(|| value.as_object().map(|_: &Object| "抛出了非 Error 对象".to_string()))
            .unwrap_or_else(|| format!("{value:?}")),
        CaughtError::Error(error) => error.to_string(),
    }
}

/// First `eval_script:LINE:COL` position in a QuickJS stack.
fn script_line(stack: &str) -> Option<u32> {
    stack.lines().find_map(|line| {
        let start = line.find("eval_script:")? + "eval_script:".len();
        let digits: String = line[start..].chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Value, serde_yaml::Error> {
        serde_yaml::from_str(text)
    }

    fn run(base: &str, text: &str) -> Result<Value, String> {
        let mut value: Value = serde_yaml::from_str(base).unwrap();
        apply(&mut value, text, "demo", parse)?;
        Ok(value)
    }

    fn rules(value: &Value) -> Vec<String> {
        value["rules"].as_sequence().unwrap().iter().map(|item| item.as_str().unwrap().to_string()).collect()
    }

    const BASE: &str = "mixed-port: 7890\ndns:\n  enable: true\n  ipv6: true\n  nameserver: [a]\n  nameserver-policy:\n    '+.google.cn': [1.1.1.1]\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,proxy\n";

    #[test]
    fn plain_keys_deep_merge_mappings_and_replace_lists() {
        let value = run(BASE, "mixed-port: 7891\ndns:\n  ipv6: false\nrules:\n  - MATCH,DIRECT\n").unwrap();
        assert_eq!(value["mixed-port"], 7891);
        assert_eq!(value["dns"]["ipv6"], false);
        assert_eq!(value["dns"]["enable"], true, "sibling keys survive a merge");
        assert_eq!(rules(&value), ["MATCH,DIRECT"]);
    }

    #[test]
    fn plus_prepends_and_appends_lists() {
        let value = run(BASE, "+rules:\n  - DOMAIN-SUFFIX,corp.com,DIRECT\nrules+:\n  - DOMAIN,tail.com,DIRECT\n").unwrap();
        assert_eq!(rules(&value), ["DOMAIN-SUFFIX,corp.com,DIRECT", "GEOIP,CN,DIRECT", "MATCH,proxy", "DOMAIN,tail.com,DIRECT"]);
        let nested = run(BASE, "dns:\n  +nameserver: [b]\n").unwrap();
        assert_eq!(nested["dns"]["nameserver"], serde_yaml::from_str::<Value>("[b, a]").unwrap());
        let created = run("mixed-port: 1\n", "+rules: ['MATCH,DIRECT']\n").unwrap();
        assert_eq!(rules(&created), ["MATCH,DIRECT"]);
    }

    #[test]
    fn bang_replaces_a_whole_mapping() {
        let value = run(BASE, "dns!:\n  enable: false\n").unwrap();
        assert_eq!(value["dns"], serde_yaml::from_str::<Value>("enable: false").unwrap());
    }

    #[test]
    fn angle_brackets_quote_keys_with_plus() {
        let value = run(BASE, "dns:\n  nameserver-policy:\n    <+.google.cn>: [8.8.8.8]\n    +<+.example.com>: [9.9.9.9]\n").unwrap();
        let policy = &value["dns"]["nameserver-policy"];
        assert_eq!(policy["+.google.cn"], serde_yaml::from_str::<Value>("[8.8.8.8]").unwrap());
        assert_eq!(policy["+.example.com"], serde_yaml::from_str::<Value>("[9.9.9.9]").unwrap());
        let appended = run(BASE, "dns:\n  nameserver-policy:\n    <+.google.cn>+: [8.8.8.8]\n").unwrap();
        assert_eq!(appended["dns"]["nameserver-policy"]["+.google.cn"], serde_yaml::from_str::<Value>("[1.1.1.1, 8.8.8.8]").unwrap());
    }

    #[test]
    fn verge_prepend_keys_are_supported_at_the_top_level() {
        let value = run(BASE, "prepend-rules: ['DOMAIN,a.com,DIRECT']\nappend-rules: ['DOMAIN,z.com,DIRECT']\n").unwrap();
        assert_eq!(rules(&value).first().unwrap(), "DOMAIN,a.com,DIRECT");
        assert_eq!(rules(&value).last().unwrap(), "DOMAIN,z.com,DIRECT");
        assert!(value.get("prepend-rules").is_none());
    }

    #[test]
    fn yaml_errors_report_the_line() {
        let error = run(BASE, "dns:\n  enable: [\n").unwrap_err();
        assert!(error.starts_with("YAML 第"), "{error}");
        assert!(run(BASE, "- a\n").unwrap_err().contains("键值对"));
    }

    #[test]
    fn scripts_are_detected_by_a_top_level_main() {
        assert_eq!(kind_of("function main(config) {\n  return config\n}\n"), OverrideKind::Script);
        assert_eq!(kind_of("// note\nconst main = (config) => config\n"), OverrideKind::Script);
        assert_eq!(kind_of("async function main (c) { return c }"), OverrideKind::Script);
        assert_eq!(kind_of("rules:\n  - MATCH,DIRECT\n"), OverrideKind::Yaml);
        assert_eq!(kind_of("script:\n  code: |\n    function main(c) { return c }\n"), OverrideKind::Yaml);
    }

    #[test]
    fn script_main_edits_the_config_and_logs() {
        let script = "function main(config, name) {\n  console.log('profile', name, config.rules.length)\n  config.rules.unshift('DOMAIN-SUFFIX,corp.com,DIRECT')\n  config['mixed-port'] = 7999\n  return config\n}\n";
        let mut value: Value = serde_yaml::from_str(BASE).unwrap();
        let applied = apply(&mut value, script, "demo", parse).unwrap();
        assert_eq!(rules(&value)[0], "DOMAIN-SUFFIX,corp.com,DIRECT");
        assert_eq!(value["mixed-port"], 7999);
        assert_eq!(applied.logs, ["profile demo 2"]);
    }

    #[test]
    fn script_may_mutate_without_returning_or_be_async() {
        let value = run(BASE, "function main(config) { config.mode = 'global' }").unwrap();
        assert_eq!(value["mode"], "global");
        let value = run(BASE, "async function main(config) { await null; config.mode = 'direct'; return config }").unwrap();
        assert_eq!(value["mode"], "direct");
    }

    #[test]
    fn script_errors_are_reported_with_lines() {
        let error = run(BASE, "function main(config) {\n  return config.missing.value\n}\n").unwrap_err();
        assert!(error.starts_with("main 运行出错"), "{error}");
        assert!(error.contains("第 2 行"), "{error}");
        let syntax = run(BASE, "function main(config) {\n  return config +\n").unwrap_err();
        assert!(syntax.starts_with("脚本有误"), "{syntax}");
        assert!(syntax.contains("行"), "{syntax}");
        assert!(run(BASE, "function main(config) { return [1] }").unwrap_err().contains("配置对象"));
        assert!(run(BASE, "const main = 1\n").unwrap_err().contains("function main"));
    }

    #[test]
    fn runaway_scripts_are_stopped() {
        let error = run(BASE, "function main(config) { while (true) {} }").unwrap_err();
        assert!(error.contains("已中止"), "{error}");
    }
}
