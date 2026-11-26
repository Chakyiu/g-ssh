//! Audit rows for MCP tool calls.
//!
//! `mcp-audit.json` in the app data directory is a JSON array. Each row is one
//! tool call: when, which tool, the host the caller named, the request text,
//! and whether it succeeded. Command output and vault secrets are not stored.
//!
//! Retention is `mcp_audit_retention_days` in `preferences.json`. A missing or
//! unreadable value means [`DEFAULT_RETENTION_DAYS`]. `0` is kept as one day.
//! Values above [`MAX_RETENTION_DAYS`] are kept as that maximum.
//!
//! Rows older than the period are deleted when a call is recorded, when the
//! MCP server starts, and when Settings saves the period. Shortening the
//! period deletes rows that are now too old. Lengthening it does not restore
//! rows already deleted. The call recorded in that same pass is new, so it
//! stays. A change made while a call is still running applies when that call
//! is recorded, using the period on disk at that moment.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DEFAULT_RETENTION_DAYS: u32 = 30;
pub const MIN_RETENTION_DAYS: u32 = 1;
pub const MAX_RETENTION_DAYS: u32 = 3650;

const LOG_NAME: &str = "mcp-audit.json";
const LOCK_NAME: &str = "mcp-audit.lock";
const PREF_NAME: &str = "preferences.json";
const PREF_KEY: &str = "mcp_audit_retention_days";
const MAX_REQUEST_CHARS: usize = 1024;
const MAX_ERROR_CHARS: usize = 512;
const MAX_HOST_CHARS: usize = 256;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
// shortcut: lock file, not an OS lock. A crash holds the log for up to 30s; switch to flock if that wait shows up.
const STALE_LOCK: Duration = Duration::from_secs(30);
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// One MCP tool call, before it is clipped and stored.
#[derive(Clone, Debug)]
pub struct CommandAudit {
    pub tool: String,
    pub host: Option<String>,
    pub request: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Row {
    id: Uuid,
    at_ms: u64,
    tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    request: String,
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Append one row, then drop rows older than the configured period.
pub fn record(audit: CommandAudit) -> Result<(), String> {
    let dir = data_dir()?;
    record_at(&dir, audit, now_ms())
}

/// Delete stored rows older than the period currently in preferences.
///
/// Returns how many rows were removed. A missing log removes nothing.
pub fn prune() -> Result<usize, String> {
    let dir = data_dir()?;
    prune_at(&dir, now_ms())
}

/// A hand-edited period outside `1..=3650` becomes the nearest bound.
pub fn clamp_retention_days(days: u64) -> u32 {
    let days = u32::try_from(days).unwrap_or(MAX_RETENTION_DAYS);
    days.clamp(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)
}

fn data_dir() -> Result<PathBuf, String> {
    crate::vault::app_data_dir().ok_or_else(|| "no data directory for the MCP audit log".into())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn record_at(dir: &Path, audit: CommandAudit, now_ms: u64) -> Result<(), String> {
    let _lock = acquire_lock(dir)?;
    let path = dir.join(LOG_NAME);
    let mut rows = load_or_quarantine(&path)?;
    rows.push(Row::from_audit(audit, now_ms));
    apply_retention(dir, now_ms, &mut rows);
    write_rows(&path, &rows)
}

fn prune_at(dir: &Path, now_ms: u64) -> Result<usize, String> {
    let _lock = acquire_lock(dir)?;
    let path = dir.join(LOG_NAME);
    if !path.exists() {
        return Ok(0);
    }
    let mut rows = load_or_quarantine(&path)?;
    let before = rows.len();
    apply_retention(dir, now_ms, &mut rows);
    let removed = before - rows.len();
    if removed > 0 {
        write_rows(&path, &rows)?;
    }
    Ok(removed)
}

fn apply_retention(dir: &Path, now_ms: u64, rows: &mut Vec<Row>) {
    let cutoff = cutoff_ms(now_ms, retention_days_in(dir));
    rows.retain(|row| row.at_ms >= cutoff);
}

fn cutoff_ms(now_ms: u64, days: u32) -> u64 {
    now_ms.saturating_sub(u64::from(days).saturating_mul(DAY_MS))
}

fn retention_days_in(dir: &Path) -> u32 {
    let Ok(bytes) = std::fs::read(dir.join(PREF_NAME)) else {
        return DEFAULT_RETENTION_DAYS;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return DEFAULT_RETENTION_DAYS;
    };
    match value.get(PREF_KEY) {
        Some(serde_json::Value::Number(number)) => number
            .as_u64()
            .map(clamp_retention_days)
            .unwrap_or(DEFAULT_RETENTION_DAYS),
        _ => DEFAULT_RETENTION_DAYS,
    }
}

impl Row {
    fn from_audit(audit: CommandAudit, at_ms: u64) -> Self {
        let tool = clip(&audit.tool, MAX_HOST_CHARS);
        let tool = if tool.is_empty() {
            "unknown".to_string()
        } else {
            tool
        };
        let host = audit
            .host
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(|host| clip(host, MAX_HOST_CHARS));
        let error = if audit.ok {
            None
        } else {
            Some(match audit.error.as_deref() {
                Some(error) if !error.trim().is_empty() => clip(error.trim(), MAX_ERROR_CHARS),
                _ => "failed".to_string(),
            })
        };
        Self {
            id: Uuid::new_v4(),
            at_ms,
            tool,
            host,
            request: clip(&audit.request, MAX_REQUEST_CHARS),
            ok: audit.ok,
            error,
        }
    }
}

fn clip(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut chars = text.chars().filter(|ch| *ch != '\0');
    for _ in 0..max_chars {
        match chars.next() {
            Some(ch) => out.push(ch),
            None => return out,
        }
    }
    if chars.next().is_some() && max_chars > 0 {
        out.pop();
        out.push('…');
    }
    out
}

fn load_or_quarantine(path: &Path) -> Result<Vec<Row>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    };
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    match serde_json::from_slice::<Vec<Row>>(&bytes) {
        Ok(rows) => Ok(rows),
        Err(error) => {
            quarantine(path)?;
            tracing::error!(
                %error,
                path = %path.display(),
                "mcp audit log was unreadable and was moved aside"
            );
            Ok(Vec::new())
        }
    }
}

fn quarantine(path: &Path) -> Result<(), String> {
    let mut dest = path.with_extension("json.corrupt");
    if dest.exists() {
        dest = path.with_file_name(format!("mcp-audit-{}.json.corrupt", now_ms()));
    }
    std::fs::rename(path, &dest).map_err(|error| error.to_string())
}

fn write_rows(path: &Path, rows: &[Row]) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(rows).map_err(|error| error.to_string())?;
    crate::vault::storage::write_atomic(path, &bytes).map_err(|error| error.to_string())
}

struct AuditLock {
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl Drop for AuditLock {
    fn drop(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

fn acquire_lock(dir: &Path) -> Result<AuditLock, String> {
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    let path = dir.join(LOCK_NAME);
    let started = std::time::Instant::now();
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                return Ok(AuditLock {
                    path,
                    file: Some(file),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if lock_is_stale(&path) {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if started.elapsed() > LOCK_WAIT {
                    return Err("MCP audit log is busy".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn lock_is_stale(path: &Path) -> bool {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age > STALE_LOCK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(tool: &str, request: &str, ok: bool) -> CommandAudit {
        CommandAudit {
            tool: tool.into(),
            host: Some("web".into()),
            request: request.into(),
            ok,
            error: if ok {
                None
            } else {
                Some("connection closed".into())
            },
        }
    }

    fn write_days(dir: &Path, days: &str) {
        std::fs::write(
            dir.join(PREF_NAME),
            format!(r#"{{"theme":"light","{PREF_KEY}":{days}}}"#),
        )
        .unwrap();
    }

    #[test]
    fn missing_or_unreadable_retention_is_thirty_days_and_bounds_clamp() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(retention_days_in(dir.path()), DEFAULT_RETENTION_DAYS);

        std::fs::write(dir.path().join(PREF_NAME), b"{}").unwrap();
        assert_eq!(retention_days_in(dir.path()), 30);

        write_days(dir.path(), "0");
        assert_eq!(retention_days_in(dir.path()), 1);
        write_days(dir.path(), "99999");
        assert_eq!(retention_days_in(dir.path()), MAX_RETENTION_DAYS);
        write_days(dir.path(), "\"30\"");
        assert_eq!(retention_days_in(dir.path()), DEFAULT_RETENTION_DAYS);
        std::fs::write(dir.path().join(PREF_NAME), b"not json").unwrap();
        assert_eq!(retention_days_in(dir.path()), DEFAULT_RETENTION_DAYS);
    }

    #[test]
    fn a_recorded_call_keeps_metadata_and_drops_rows_past_retention() {
        let dir = tempfile::tempdir().unwrap();
        write_days(dir.path(), "1");
        let day = DAY_MS;
        record_at(dir.path(), audit("ssh_exec", "uname -a", true), 1_000).unwrap();
        record_at(
            dir.path(),
            audit("list_hosts", "", false),
            1_000 + day + day,
        )
        .unwrap();

        let rows: Vec<Row> =
            serde_json::from_slice(&std::fs::read(dir.path().join(LOG_NAME)).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "list_hosts");
        assert_eq!(rows[0].host.as_deref(), Some("web"));
        assert!(!rows[0].ok);
        assert_eq!(rows[0].error.as_deref(), Some("connection closed"));
        assert!(rows[0].at_ms > 0);
        assert!(!rows[0].id.is_nil());
    }

    #[test]
    fn shortening_retention_drops_rows_and_lengthening_does_not_restore_them() {
        let dir = tempfile::tempdir().unwrap();
        write_days(dir.path(), "30");
        let start = 10 * DAY_MS;
        record_at(dir.path(), audit("ssh_exec", "uptime", true), start).unwrap();

        write_days(dir.path(), "1");
        let removed = prune_at(dir.path(), start + 10 * DAY_MS).unwrap();
        assert_eq!(removed, 1);
        let after_short: Vec<Row> =
            serde_json::from_slice(&std::fs::read(dir.path().join(LOG_NAME)).unwrap()).unwrap();
        assert!(after_short.is_empty());

        write_days(dir.path(), "30");
        let removed = prune_at(dir.path(), start + 10 * DAY_MS).unwrap();
        assert_eq!(removed, 0);
        let after_long: Vec<Row> =
            serde_json::from_slice(&std::fs::read(dir.path().join(LOG_NAME)).unwrap()).unwrap();
        assert!(after_long.is_empty());
    }

    #[test]
    fn the_row_just_recorded_survives_that_pass() {
        let dir = tempfile::tempdir().unwrap();
        write_days(dir.path(), "1");
        let now = 5 * DAY_MS;
        record_at(dir.path(), audit("stop_forward", "fwd-1", true), now).unwrap();
        let rows: Vec<Row> =
            serde_json::from_slice(&std::fs::read(dir.path().join(LOG_NAME)).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].request, "fwd-1");
        assert!(rows[0].error.is_none());
    }

    #[test]
    fn long_request_text_is_clipped_and_output_is_not_a_field() {
        let dir = tempfile::tempdir().unwrap();
        let request = "a".repeat(MAX_REQUEST_CHARS + 40);
        record_at(dir.path(), audit("ssh_exec", &request, true), 50).unwrap();
        let file = std::fs::read_to_string(dir.path().join(LOG_NAME)).unwrap();
        assert!(!file.contains(&request));
        assert!(file.contains('…'));
        assert!(!file.contains("stdout"));
        let rows: Vec<Row> = serde_json::from_str(&file).unwrap();
        assert_eq!(rows[0].request.chars().count(), MAX_REQUEST_CHARS);
    }

    #[test]
    fn an_unreadable_log_is_moved_aside_and_the_new_row_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOG_NAME);
        std::fs::write(&path, b"{not an array").unwrap();
        record_at(dir.path(), audit("start_forward", "local 1", true), 80).unwrap();
        assert!(dir.path().read_dir().unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("corrupt")));
        let rows: Vec<Row> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "start_forward");
    }
}
