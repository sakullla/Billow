//! Traffic history (R43).
//!
//! Off by default. While it is on, a background thread samples the controller's
//! `/connections` once a second and folds the per-connection counter deltas into
//! `date × profile × group × node` buckets in `traffic-history.json`. Names are
//! frozen when a sample lands, so renaming or deleting a profile or a node later
//! keeps the history readable under its old name. The file is a plain aggregate,
//! never part of a backup (R38), and everything older than [`RETENTION_DAYS`] is
//! dropped on load and on every write.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::diagnostics::civil_from_days;

/// Records older than this many days (including today) are removed.
pub const RETENTION_DAYS: i64 = 90;
/// Writes at most this often; a crash loses at most this many samples.
const SAMPLES_PER_WRITE: u32 = 60;

const VERSION: u32 = 1;
/// Built-in policies have no profile group or exit server of their own, so their
/// traffic is shown as one "Direct" row (R43).
const DIRECT_POLICIES: [&str; 4] = ["DIRECT", "REJECT", "REJECT-DROP", "PASS"];

/// One aggregated row: how much traffic one profile sent through one group and
/// node on one local date.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrafficEntry {
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub node: String,
    /// DIRECT / REJECT traffic, which has no real group or node.
    #[serde(default)]
    pub direct: bool,
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
}

/// A dated row for the stats view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatedTrafficEntry {
    pub date: String,
    #[serde(flatten)]
    pub entry: TrafficEntry,
}

#[derive(Serialize, Deserialize)]
struct HistoryFile {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    days: BTreeMap<String, Vec<TrafficEntry>>,
}

fn default_version() -> u32 {
    VERSION
}

type BucketKey = (String, String, String);
type DayBuckets = BTreeMap<BucketKey, TrafficEntry>;

/// In-memory aggregate plus the file it is written to. Shared by the recorder
/// thread and the stats commands behind one mutex.
pub struct TrafficHistory {
    path: PathBuf,
    /// Mirrors the stored setting so a sample that races a switch-off is dropped.
    enabled: bool,
    days: BTreeMap<String, DayBuckets>,
    /// Last upload/download counter per connection id. Never persisted: a new
    /// process cannot see the counters of connections the old one sampled.
    baselines: HashMap<String, (u64, u64)>,
    /// Right after "clear all" the next sample only re-seeds the baselines, so
    /// the bytes already counted before the clear do not come back.
    pending_clear: bool,
    samples_since_write: u32,
    dirty: bool,
}

impl TrafficHistory {
    /// Read the file next to the other app data. A missing, damaged or newer file
    /// starts empty instead of failing the app.
    pub fn open(path: PathBuf) -> Self {
        let mut history = Self {
            path,
            enabled: false,
            days: BTreeMap::new(),
            baselines: HashMap::new(),
            pending_clear: false,
            samples_since_write: 0,
            dirty: false,
        };
        history.load();
        history
    }

    fn load(&mut self) {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return;
        };
        let Ok(file) = serde_json::from_str::<HistoryFile>(&text) else {
            return;
        };
        if file.version != VERSION {
            // A newer file may use another layout; keep the app running with an
            // empty history instead of guessing at its rows.
            return;
        }
        for (date, rows) in file.days {
            if parse_date(&date).is_none() {
                continue;
            }
            let day = self.days.entry(date).or_default();
            for row in rows {
                let key = (row.profile.clone(), row.group.clone(), row.node.clone());
                let entry = day.entry(key).or_insert_with(|| TrafficEntry {
                    direct: row.direct,
                    ..TrafficEntry::default()
                });
                entry.upload = entry.upload.saturating_add(row.upload);
                entry.download = entry.download.saturating_add(row.download);
            }
        }
        self.dirty = false;
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Reflect the stored switch. Turning it off drops the id table at once, so
    /// re-enabling starts from fresh counters and no traffic is counted twice.
    pub fn set_enabled(&mut self, enabled: bool) {
        if self.enabled == enabled {
            return;
        }
        self.enabled = enabled;
        self.baselines.clear();
        if !enabled {
            self.pending_clear = false;
            self.save_if_dirty();
        }
    }

    pub fn reset_baselines(&mut self) {
        self.baselines.clear();
        self.pending_clear = false;
    }

    /// Fold one `/connections` sample into today's buckets. Returns whether any
    /// counter moved. A sample taken while recording is off changes nothing.
    pub fn record(
        &mut self,
        date: &str,
        profile: &str,
        connections: &[crate::diagnostics::ConnectionTraffic],
    ) -> bool {
        if !self.enabled || parse_date(date).is_none() {
            return false;
        }
        let profile = profile.trim();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut changed = false;
        for connection in connections {
            let Some((group, node, direct)) = attribution(&connection.chains) else {
                continue;
            };
            seen.insert(connection.id.as_str());
            let last = self.baselines.get(&connection.id).copied();
            self.baselines.insert(
                connection.id.clone(),
                (connection.upload, connection.download),
            );
            let (upload, download) = match last {
                // After clear-all the first sight of a connection only seeds the
                // baseline: those bytes were already on screen before the clear.
                None if self.pending_clear => (0, 0),
                None => (connection.upload, connection.download),
                Some((up, down)) => (
                    connection.upload.saturating_sub(up),
                    connection.download.saturating_sub(down),
                ),
            };
            if upload == 0 && download == 0 {
                continue;
            }
            let entry = self
                .days
                .entry(date.to_string())
                .or_default()
                .entry((profile.to_string(), group.clone(), node.clone()))
                .or_insert_with(|| TrafficEntry {
                    profile: profile.to_string(),
                    group,
                    node,
                    direct,
                    upload: 0,
                    download: 0,
                });
            entry.upload = entry.upload.saturating_add(upload);
            entry.download = entry.download.saturating_add(download);
            changed = true;
        }
        self.pending_clear = false;
        // Closed connections keep no counter of their own; a stale id would only
        // grow the table while the app runs.
        self.baselines.retain(|id, _| seen.contains(id.as_str()));
        self.dirty |= changed;
        self.samples_since_write += 1;
        if self.samples_since_write >= SAMPLES_PER_WRITE {
            self.housekeeping(date);
        }
        changed
    }

    /// Persist on a timer and drop expired days.
    fn housekeeping(&mut self, today: &str) {
        self.samples_since_write = 0;
        self.prune(today);
        self.save_if_dirty();
    }

    /// Delete days outside the retention window.
    pub fn prune(&mut self, today: &str) {
        let Some(today_days) = parse_date(today) else {
            return;
        };
        let oldest = today_days - (RETENTION_DAYS - 1);
        let before = self.days.len();
        self.days.retain(|date, _| match parse_date(date) {
            Some(days) => days >= oldest,
            None => false,
        });
        if self.days.len() != before {
            self.dirty = true;
        }
    }

    /// Drop every record. While recording is on the next sample only refreshes
    /// the id table, so the view stays empty until new traffic arrives.
    pub fn clear(&mut self) {
        self.days.clear();
        self.baselines.clear();
        self.pending_clear = self.enabled;
        self.dirty = true;
        self.samples_since_write = 0;
        self.save_if_dirty();
    }

    /// Rows inside `[from, to]`, newest date first, larger totals first.
    pub fn entries(&self, from: &str, to: &str) -> Vec<DatedTrafficEntry> {
        let (Some(from), Some(to)) = (parse_date(from), parse_date(to)) else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for (date, buckets) in self.days.iter().rev() {
            let Some(days) = parse_date(date) else {
                continue;
            };
            if days < from || days > to {
                continue;
            }
            for entry in buckets.values() {
                rows.push(DatedTrafficEntry {
                    date: date.clone(),
                    entry: entry.clone(),
                });
            }
        }
        rows.sort_by(|left, right| {
            right
                .date
                .cmp(&left.date)
                .then_with(|| total(&right.entry).cmp(&total(&left.entry)))
                .then_with(|| left.entry.profile.cmp(&right.entry.profile))
                .then_with(|| left.entry.group.cmp(&right.entry.group))
                .then_with(|| left.entry.node.cmp(&right.entry.node))
        });
        rows
    }

    /// Total bytes per local date inside `[from, to]`, including days with no
    /// traffic so the bar chart keeps an even axis.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn daily(&self, from: &str, to: &str) -> Vec<(String, u64, u64)> {
        let (Some(from_days), Some(to_days)) = (parse_date(from), parse_date(to)) else {
            return Vec::new();
        };
        if to_days < from_days {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut day = from_days;
        while day <= to_days {
            let date = date_from_days(day);
            let mut upload = 0u64;
            let mut download = 0u64;
            if let Some(buckets) = self.days.get(&date) {
                for entry in buckets.values() {
                    upload = upload.saturating_add(entry.upload);
                    download = download.saturating_add(entry.download);
                }
            }
            out.push((date, upload, download));
            day += 1;
        }
        out
    }

    pub fn save_if_dirty(&mut self) {
        if !self.dirty {
            return;
        }
        if self.save().is_ok() {
            self.dirty = false;
        }
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| err.to_string())?;
            }
        }
        let file = HistoryFile {
            version: VERSION,
            days: self
                .days
                .iter()
                .map(|(date, buckets)| (date.clone(), buckets.values().cloned().collect()))
                .collect(),
        };
        let data = serde_json::to_vec(&file).map_err(|err| err.to_string())?;
        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, data).map_err(|err| err.to_string())?;
        fs::rename(&temporary, &self.path).map_err(|err| err.to_string())
    }

    #[cfg(test)]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

fn total(entry: &TrafficEntry) -> u64 {
    entry.upload.saturating_add(entry.download)
}

/// Group, node and whether this is built-in direct/reject traffic. Mihomo lists
/// `chains` from the exit server back to the rule's target, so the first name is
/// the exit node and the last one the policy group.
pub fn attribution(chains: &[String]) -> Option<(String, String, bool)> {
    let node = chains.first().map(String::as_str).unwrap_or("").trim();
    let group = chains.last().map(String::as_str).unwrap_or("").trim();
    if node.is_empty() && group.is_empty() {
        return None;
    }
    let upper = node.to_ascii_uppercase();
    if DIRECT_POLICIES.contains(&upper.as_str())
        || DIRECT_POLICIES.contains(&group.to_ascii_uppercase().as_str())
    {
        return Some((String::new(), String::new(), true));
    }
    let group = if group.is_empty() { node } else { group };
    Some((group.to_string(), node.to_string(), false))
}

/// Resolve a stats request into inclusive local dates, clamped to the retained
/// window. Unknown values fall back to today instead of failing the dialog.
pub fn range_bounds(
    range: &str,
    from: Option<&str>,
    to: Option<&str>,
    today: &str,
) -> (String, String) {
    let Some(today_days) = parse_date(today) else {
        return (today.to_string(), today.to_string());
    };
    let oldest = today_days - (RETENTION_DAYS - 1);
    let clamp = |days: i64| days.clamp(oldest, today_days);
    match range {
        "7d" => (date_from_days(clamp(today_days - 6)), today.to_string()),
        "30d" => (date_from_days(clamp(today_days - 29)), today.to_string()),
        "custom" => {
            let mut start = from.and_then(parse_date).map(clamp).unwrap_or(today_days);
            let mut end = to.and_then(parse_date).map(clamp).unwrap_or(today_days);
            if start > end {
                std::mem::swap(&mut start, &mut end);
            }
            (date_from_days(start), date_from_days(end))
        }
        _ => (today.to_string(), today.to_string()),
    }
}

fn days_in_month(year: i64, month: u32) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 30,
    }
}

/// Days since 1970-01-01 for a valid civil date.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 } as i64;
    let day_of_year = (153 * month_index + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

pub fn parse_date(text: &str) -> Option<i64> {
    let mut parts = text.trim().split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || day == 0 {
        return None;
    }
    if day as i64 > days_in_month(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

pub fn date_from_days(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The user's local calendar date, which is what a traffic day means.
pub fn today() -> String {
    match local_date_parts() {
        Some((year, month, day)) => format!("{year:04}-{month:02}-{day:02}"),
        None => date_from_days(utc_days_now()),
    }
}

fn utc_days_now() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    seconds.div_euclid(86_400)
}

#[cfg(windows)]
fn local_date_parts() -> Option<(i64, u32, u32)> {
    // `std` has no local time; one Win32 call is cheaper than a dependency.
    #[repr(C)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLocalTime(value: *mut SystemTime);
    }
    let mut value = std::mem::MaybeUninit::<SystemTime>::zeroed();
    // SAFETY: GetLocalTime writes one SYSTEMTIME into the pointer it is given.
    unsafe { GetLocalTime(value.as_mut_ptr()) };
    // SAFETY: the call above initialized every field.
    let value = unsafe { value.assume_init() };
    Some((value.year as i64, value.month as u32, value.day as u32))
}

#[cfg(unix)]
fn local_date_parts() -> Option<(i64, u32, u32)> {
    use std::os::raw::{c_char, c_int, c_long};
    // `time_t` follows the pointer width on every platform Billow builds for;
    // matching it avoids handing `localtime_r` a wrong-sized value on 32-bit.
    #[cfg(target_pointer_width = "32")]
    type TimeT = i32;
    #[cfg(target_pointer_width = "64")]
    type TimeT = i64;
    // POSIX `struct tm`; only the first six fields are read. The tail exists so
    // the platform's own layout is not overwritten.
    #[repr(C)]
    struct Tm {
        tm_sec: c_int,
        tm_min: c_int,
        tm_hour: c_int,
        tm_mday: c_int,
        tm_mon: c_int,
        tm_year: c_int,
        tm_wday: c_int,
        tm_yday: c_int,
        tm_isdst: c_int,
        tm_gmtoff: c_long,
        tm_zone: *const c_char,
    }
    unsafe extern "C" {
        fn localtime_r(timep: *const TimeT, result: *mut Tm) -> *mut Tm;
    }
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as TimeT;
    let mut value = std::mem::MaybeUninit::<Tm>::zeroed();
    // SAFETY: localtime_r fills one struct tm and the input lives for the call.
    let filled = unsafe { localtime_r(&seconds, value.as_mut_ptr()) };
    if filled.is_null() {
        return None;
    }
    // SAFETY: localtime_r succeeded, so every field was written.
    let value = unsafe { value.assume_init() };
    Some((
        value.tm_year as i64 + 1900,
        (value.tm_mon + 1) as u32,
        value.tm_mday as u32,
    ))
}

#[cfg(not(any(windows, unix)))]
fn local_date_parts() -> Option<(i64, u32, u32)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::ConnectionTraffic;

    fn connection(id: &str, chains: &[&str], upload: u64, download: u64) -> ConnectionTraffic {
        ConnectionTraffic {
            id: id.to_string(),
            chains: chains.iter().map(|item| item.to_string()).collect(),
            upload,
            download,
        }
    }

    fn temporary_history(name: &str) -> TrafficHistory {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "billow-traffic-{name}-{}-{nanos}",
            std::process::id()
        ));
        TrafficHistory::open(dir.join("traffic-history.json"))
    }

    #[test]
    fn dates_round_trip_and_reject_nonsense() {
        assert_eq!(date_from_days(days_from_civil(2026, 11, 20)), "2026-11-20");
        assert_eq!(
            parse_date("2026-11-20"),
            Some(days_from_civil(2026, 11, 20))
        );
        assert_eq!(parse_date("2024-02-29"), Some(days_from_civil(2024, 2, 29)));
        assert_eq!(parse_date("2026-02-29"), None);
        assert_eq!(parse_date("2026-13-01"), None);
        assert_eq!(parse_date("2026-00-10"), None);
        assert_eq!(parse_date("2026-1"), None);
        assert_eq!(parse_date("not-a-date"), None);
    }

    #[test]
    fn chains_map_to_group_and_exit_node_with_direct_kept_apart() {
        let chains = ["香港 01".to_string(), "节点选择".to_string()];
        assert_eq!(
            attribution(&chains),
            Some(("节点选择".to_string(), "香港 01".to_string(), false))
        );
        // A single-hop chain has the node as its own group, so it still groups.
        let single = ["香港 01".to_string()];
        assert_eq!(
            attribution(&single),
            Some(("香港 01".to_string(), "香港 01".to_string(), false))
        );
        for policy in ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "direct"] {
            let chains = [policy.to_string()];
            assert_eq!(
                attribution(&chains),
                Some((String::new(), String::new(), true))
            );
        }
        assert_eq!(attribution(&[]), None);
    }

    #[test]
    fn one_connection_sampled_repeatedly_counts_each_delta_once() {
        let mut history = temporary_history("deltas");
        history.set_enabled(true);
        let date = "2026-11-20";
        let chain = ["香港 01", "节点选择"];

        assert!(history.record(date, "星河云", &[connection("c1", &chain, 1_000, 4_000)]));
        // Same counters: nothing new.
        assert!(!history.record(date, "星河云", &[connection("c1", &chain, 1_000, 4_000)]));
        // 500 up / 2_000 down more.
        assert!(history.record(date, "星河云", &[connection("c1", &chain, 1_500, 6_000)]));

        let rows = history.entries(date, date);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entry.upload, 1_500);
        assert_eq!(rows[0].entry.download, 6_000);
        assert_eq!(rows[0].entry.profile, "星河云");
        assert_eq!(rows[0].entry.group, "节点选择");
        assert_eq!(rows[0].entry.node, "香港 01");
        assert!(!rows[0].entry.direct);
    }

    #[test]
    fn profiles_groups_and_nodes_are_counted_separately_and_direct_is_one_row() {
        let mut history = temporary_history("grouping");
        history.set_enabled(true);
        let date = "2026-11-20";
        history.record(
            date,
            "配置 A",
            &[connection("a1", &["香港 01", "节点选择"], 10, 100)],
        );
        history.record(
            date,
            "配置 B",
            &[connection("b1", &["日本 02", "自动选择"], 20, 200)],
        );
        history.record(
            date,
            "配置 A",
            &[
                connection("d1", &["DIRECT"], 5, 50),
                connection("r1", &["REJECT"], 1, 1),
            ],
        );

        let rows = history.entries(date, date);
        assert_eq!(rows.len(), 3);
        let total_for = |profile: &str| -> u64 {
            rows.iter()
                .filter(|row| row.entry.profile == profile)
                .map(|row| row.entry.download)
                .sum()
        };
        assert_eq!(total_for("配置 A"), 151);
        assert_eq!(total_for("配置 B"), 200);
        let direct: Vec<_> = rows.iter().filter(|row| row.entry.direct).collect();
        assert_eq!(direct.len(), 1);
        assert_eq!(
            direct[0].entry.download, 51,
            "DIRECT and REJECT share the Direct row"
        );
        assert_eq!(direct[0].entry.upload, 6);
        let totals: u64 = rows.iter().map(|row| total(&row.entry)).sum();
        assert_eq!(totals, 10 + 100 + 20 + 200 + 6 + 51);
    }

    #[test]
    fn a_kernel_restart_starts_a_new_id_table_instead_of_subtracting_old_counters() {
        let mut history = temporary_history("restart");
        history.set_enabled(true);
        let date = "2026-11-20";
        history.record(
            date,
            "星河云",
            &[connection("c1", &["香港 01"], 900, 9_000)],
        );
        history.reset_baselines();
        // The same id after a restart is a different connection: its counters are
        // counted from zero rather than as a negative delta.
        history.record(date, "星河云", &[connection("c1", &["香港 01"], 100, 200)]);
        let rows = history.entries(date, date);
        assert_eq!(rows[0].entry.upload, 1_000);
        assert_eq!(rows[0].entry.download, 9_200);

        // A fresh process loads the buckets but no ids: the first sample of an id
        // counts from zero and the next sample of the same id only its growth.
        let path = history.path().to_path_buf();
        history.save().unwrap();
        let mut reopened = TrafficHistory::open(path.clone());
        reopened.set_enabled(true);
        assert!(reopened.record(
            date,
            "星河云",
            &[connection("c1", &["香港 01"], 900, 9_000)]
        ));
        assert!(!reopened.record(
            date,
            "星河云",
            &[connection("c1", &["香港 01"], 900, 9_000)]
        ));
        let reopened_rows = reopened.entries(date, date);
        assert_eq!(reopened_rows[0].entry.upload, 1_900);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn closed_connections_leave_the_id_table() {
        let mut history = temporary_history("closed");
        history.set_enabled(true);
        let date = "2026-11-20";
        history.record(date, "A", &[connection("c1", &["香港 01"], 10, 10)]);
        // The next sample no longer carries c1.
        history.record(date, "A", &[connection("c2", &["香港 01"], 1, 1)]);
        assert!(!history.baselines.contains_key("c1"));
        assert!(history.baselines.contains_key("c2"));
    }

    #[test]
    fn days_past_the_retention_window_are_removed() {
        let mut history = temporary_history("retention");
        history.set_enabled(true);
        let today = "2026-11-20";
        let oldest = date_from_days(parse_date(today).unwrap() - (RETENTION_DAYS - 1));
        let too_old = date_from_days(parse_date(today).unwrap() - RETENTION_DAYS);
        history.record(&oldest, "A", &[connection("c1", &["X"], 1, 1)]);
        history.record(&too_old, "A", &[connection("c2", &["X"], 1, 1)]);
        history.prune(today);
        let dates: Vec<_> = history.days.keys().cloned().collect();
        assert_eq!(dates, vec![oldest]);
    }

    #[test]
    fn renamed_profiles_keep_their_recorded_name() {
        let mut history = temporary_history("rename");
        history.set_enabled(true);
        let date = "2026-11-20";
        history.record(date, "旧名字", &[connection("c1", &["香港 01"], 10, 100)]);
        history.record(date, "新名字", &[connection("c2", &["香港 01"], 1, 10)]);
        let rows = history.entries(date, date);
        let names: Vec<_> = rows.iter().map(|row| row.entry.profile.as_str()).collect();
        assert!(names.contains(&"旧名字"));
        assert!(names.contains(&"新名字"));
        assert_eq!(
            rows.iter()
                .find(|row| row.entry.profile == "旧名字")
                .map(|row| row.entry.download),
            Some(100),
            "the bytes recorded before the rename stay under the old name"
        );
    }

    #[test]
    fn turning_recording_off_keeps_data_and_stops_growth() {
        let mut history = temporary_history("off");
        let date = "2026-11-20";
        // Off by default: connecting and browsing records nothing.
        assert!(!history.record(date, "A", &[connection("c1", &["香港 01"], 1_000, 1_000)]));
        assert!(history.entries(date, date).is_empty());

        history.set_enabled(true);
        history.record(date, "A", &[connection("c1", &["香港 01"], 1_000, 1_000)]);
        history.set_enabled(false);
        assert!(!history.record(date, "A", &[connection("c1", &["香港 01"], 9_000, 9_000)]));
        let rows = history.entries(date, date);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entry.upload, 1_000);

        // The switch is stored, so a restart keeps the data and the off state.
        let path = history.path().to_path_buf();
        history.save().unwrap();
        let reopened = TrafficHistory::open(path.clone());
        assert!(!reopened.enabled());
        assert_eq!(reopened.entries(date, date)[0].entry.upload, 1_000);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn clear_all_empties_the_view_and_does_not_recount_the_same_bytes() {
        let mut history = temporary_history("clear");
        history.set_enabled(true);
        let date = "2026-11-20";
        history.record(date, "A", &[connection("c1", &["香港 01"], 500, 800)]);
        history.clear();
        assert!(history.entries(date, date).is_empty());
        // The open connection is sampled again with its old counters: those bytes
        // were already cleared, so only growth after the clear is recorded.
        history.record(date, "A", &[connection("c1", &["香港 01"], 550, 900)]);
        assert!(history.entries(date, date).is_empty());
        history.record(date, "A", &[connection("c1", &["香港 01"], 600, 1_000)]);
        let rows = history.entries(date, date);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entry.upload, 50);
        assert_eq!(rows[0].entry.download, 100);
    }

    #[test]
    fn stats_ranges_stay_inside_the_retained_window() {
        let today = "2026-11-20";
        assert_eq!(
            range_bounds("today", None, None, today),
            (today.to_string(), today.to_string())
        );
        assert_eq!(
            range_bounds("7d", None, None, today),
            ("2026-11-14".to_string(), today.to_string())
        );
        assert_eq!(
            range_bounds("30d", None, None, today),
            ("2026-10-22".to_string(), today.to_string())
        );
        assert_eq!(
            range_bounds("custom", Some("2026-11-01"), Some("2026-11-03"), today),
            ("2026-11-01".to_string(), "2026-11-03".to_string())
        );
        // Reversed dates are swapped, and anything outside the window is clamped.
        assert_eq!(
            range_bounds("custom", Some("2026-11-03"), Some("2026-11-01"), today),
            ("2026-11-01".to_string(), "2026-11-03".to_string())
        );
        assert_eq!(
            range_bounds("custom", Some("2020-01-01"), Some("2030-01-01"), today),
            ("2026-08-23".to_string(), today.to_string())
        );
        assert_eq!(
            range_bounds("custom", Some("nope"), None, today),
            (today.to_string(), today.to_string())
        );
        assert_eq!(
            range_bounds("weird", None, None, today),
            (today.to_string(), today.to_string())
        );
    }

    #[test]
    fn daily_totals_fill_empty_days_for_the_chart() {
        let mut history = temporary_history("daily");
        history.set_enabled(true);
        history.record("2026-11-19", "A", &[connection("c1", &["X"], 10, 20)]);
        history.record("2026-11-20", "A", &[connection("c2", &["X"], 30, 40)]);
        let daily = history.daily("2026-11-18", "2026-11-20");
        assert_eq!(
            daily,
            vec![
                ("2026-11-18".to_string(), 0, 0),
                ("2026-11-19".to_string(), 10, 20),
                ("2026-11-20".to_string(), 30, 40),
            ]
        );
    }

    #[test]
    fn a_damaged_or_newer_file_starts_empty() {
        let date = "2026-11-20";
        for text in [
            "{not json".to_string(),
            r#"{"version":99,"days":{"2026-11-20":[{"profile":"A","group":"G","node":"N","upload":1,"download":2}]}}"#
                .to_string(),
        ] {
            let history = temporary_history("damaged");
            if let Some(parent) = history.path().parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(history.path(), text).unwrap();
            let mut reopened = TrafficHistory::open(history.path().to_path_buf());
            reopened.set_enabled(true);
            assert!(reopened.entries(date, date).is_empty());
            let _ = fs::remove_dir_all(history.path().parent().unwrap());
        }
    }
}
