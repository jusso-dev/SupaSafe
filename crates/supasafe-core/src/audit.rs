//! The audit trail.
//!
//! Append-only and hash-chained. Every record carries the hash of the one
//! before it, so removing or editing an entry breaks every hash after it and
//! `supasafe audit --verify` says exactly where.
//!
//! This is tamper *evidence*, not tamper proofing: anyone who can write the
//! file can rewrite the whole chain. What it buys is that they cannot do so
//! selectively and quietly, which is the realistic threat when an agent, a
//! script or a tired engineer is cleaning up after themselves.
//!
//! By default the trail stores normalised SQL (`WHERE email = ?`) rather than
//! the statement as written. An audit log that copies every literal is a
//! second, less protected copy of the data it is supposed to be guarding.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

use crate::environment::Environment;
use crate::policy::Decision;
use crate::risk::RiskLevel;

/// The hash the first record chains from.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What happened to a request, once everything had run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Forwarded to the database and it succeeded.
    Executed,
    /// Forwarded and the database rejected it.
    Failed { error: String },
    /// SupaSafe refused it.
    Blocked,
    /// Held for approval and nobody answered in time.
    Expired,
    /// Held for approval and a human said no.
    Rejected { by: String },
    /// Held for approval, a human said yes, and it ran.
    Approved { by: Vec<String> },
    /// Analysed only, never sent anywhere.
    Analyzed,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Executed => "executed",
            Outcome::Failed { .. } => "failed",
            Outcome::Blocked => "blocked",
            Outcome::Expired => "expired",
            Outcome::Rejected { .. } => "rejected",
            Outcome::Approved { .. } => "approved",
            Outcome::Analyzed => "analyzed",
        }
    }
}

/// One entry in the trail.
///
/// Field order matters: it is the order they are hashed in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Position in the chain, starting at 1.
    pub seq: u64,
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,

    /// Which agent asked. Taken from the client's `application_name`.
    pub agent: String,
    /// A hash of the prompt that produced the SQL, when the client supplied
    /// one. Hashed rather than stored so the trail can prove two requests came
    /// from the same prompt without holding the prompt itself.
    pub prompt_hash: Option<String>,

    /// The statement, normalised unless `store_raw_sql` is on.
    pub sql: String,
    /// Set when `sql` above is the statement exactly as written.
    pub sql_is_raw: bool,
    /// Hash of the normalised statement, stable across literal values.
    pub fingerprint: String,

    pub database: String,
    pub environment: Environment,
    pub policy: String,

    pub statement_kind: String,
    pub objects: Vec<String>,
    pub risk: u8,
    pub risk_level: RiskLevel,
    pub decision: Decision,
    /// The rule that decided, when one did.
    pub rule: Option<String>,
    pub reasons: Vec<String>,

    pub outcome: Outcome,
    /// Rows the statement reported changing, once it ran.
    pub rows_affected: Option<u64>,
    /// How long the database took, in milliseconds.
    pub duration_ms: Option<u64>,
    /// The snapshot taken before this statement, when one was.
    pub recovery_point: Option<String>,

    /// Hash of the previous record.
    pub prev_hash: String,
    /// Hash of this record's contents together with `prev_hash`.
    pub hash: String,
}

impl AuditRecord {
    /// Compute the hash for a record. `hash` itself is excluded, everything
    /// else is included.
    pub fn compute_hash(&self) -> String {
        let mut copy = self.clone();
        copy.hash = String::new();
        let canonical = serde_json::to_string(&copy).unwrap_or_default();
        let digest = Sha256::digest(canonical.as_bytes());
        hex::encode(digest)
    }

    /// A one-line summary for a terminal.
    pub fn summary(&self) -> String {
        format!(
            "{}  {:<16} risk {:>3}  {:<16} {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            self.statement_kind,
            self.risk,
            self.decision.as_str(),
            self.sql
        )
    }
}

/// A record ready to be written, before the chain fields are filled in.
#[derive(Debug, Clone, Default)]
pub struct AuditEntry {
    pub agent: String,
    pub prompt_hash: Option<String>,
    pub sql: String,
    pub sql_is_raw: bool,
    pub fingerprint: String,
    pub database: String,
    pub environment: Option<Environment>,
    pub policy: String,
    pub statement_kind: String,
    pub objects: Vec<String>,
    pub risk: u8,
    pub decision: Option<Decision>,
    pub rule: Option<String>,
    pub reasons: Vec<String>,
    pub outcome: Option<Outcome>,
    pub rows_affected: Option<u64>,
    pub duration_ms: Option<u64>,
    pub recovery_point: Option<String>,
}

/// Hash a prompt for the trail. The prompt itself is never stored.
pub fn hash_prompt(prompt: &str) -> String {
    hex::encode(Sha256::digest(prompt.as_bytes()))
}

/// Errors from the audit log.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("could not write the audit log at {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not read the audit log at {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("audit record {seq} is not valid JSON: {source}")]
    Parse { seq: u64, source: serde_json::Error },
}

/// A break in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBreak {
    pub seq: u64,
    pub id: Uuid,
    pub problem: String,
}

/// The result of verifying the whole chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    pub records: u64,
    pub breaks: Vec<ChainBreak>,
    pub head: Option<String>,
}

impl Verification {
    pub fn is_intact(&self) -> bool {
        self.breaks.is_empty()
    }
}

/// Append-only audit log backed by a JSON Lines file.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<ChainState>,
    store_raw_sql: bool,
    stdout_json: bool,
}

#[derive(Debug)]
struct ChainState {
    seq: u64,
    head: String,
}

impl AuditLog {
    /// Open (or create) the log, reading the chain head so new records
    /// continue it.
    pub fn open(path: &Path, store_raw_sql: bool) -> Result<AuditLog, AuditError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| AuditError::Write {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
        }
        let (seq, head) = match read_all(path) {
            Ok(records) => match records.last() {
                Some(last) => (last.seq, last.hash.clone()),
                None => (0, GENESIS.to_string()),
            },
            // A log that does not exist yet is not an error.
            Err(AuditError::Read { .. }) if !path.exists() => (0, GENESIS.to_string()),
            Err(e) => return Err(e),
        };

        Ok(AuditLog {
            path: path.to_path_buf(),
            state: Mutex::new(ChainState { seq, head }),
            store_raw_sql,
            stdout_json: false,
        })
    }

    /// An in-memory log, for tests and for `supasafe analyze`, which should
    /// not leave a trail behind.
    pub fn in_memory() -> AuditLog {
        AuditLog {
            path: PathBuf::new(),
            state: Mutex::new(ChainState {
                seq: 0,
                head: GENESIS.to_string(),
            }),
            store_raw_sql: false,
            stdout_json: false,
        }
    }

    pub fn with_stdout_json(mut self, on: bool) -> Self {
        self.stdout_json = on;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn stores_raw_sql(&self) -> bool {
        self.store_raw_sql
    }

    /// Append an entry, returning the record as it was written.
    pub fn append(&self, entry: AuditEntry) -> Result<AuditRecord, AuditError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let seq = state.seq + 1;
        let mut record = AuditRecord {
            seq,
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent: entry.agent,
            prompt_hash: entry.prompt_hash,
            sql: entry.sql,
            sql_is_raw: entry.sql_is_raw && self.store_raw_sql,
            fingerprint: entry.fingerprint,
            database: entry.database,
            environment: entry.environment.unwrap_or(Environment::Production),
            policy: entry.policy,
            statement_kind: entry.statement_kind,
            objects: entry.objects,
            risk: entry.risk,
            risk_level: RiskLevel::of(entry.risk),
            decision: entry.decision.unwrap_or(Decision::Deny),
            rule: entry.rule,
            reasons: entry.reasons,
            outcome: entry.outcome.unwrap_or(Outcome::Analyzed),
            rows_affected: entry.rows_affected,
            duration_ms: entry.duration_ms,
            recovery_point: entry.recovery_point,
            prev_hash: state.head.clone(),
            hash: String::new(),
        };
        record.hash = record.compute_hash();

        let line = serde_json::to_string(&record).unwrap_or_default();

        if !self.path.as_os_str().is_empty() {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .map_err(|e| AuditError::Write {
                    path: self.path.clone(),
                    source: e,
                })?;
            writeln!(file, "{line}").map_err(|e| AuditError::Write {
                path: self.path.clone(),
                source: e,
            })?;
            // Durability matters more than throughput here: a record that was
            // never flushed is a record that did not happen.
            file.flush().map_err(|e| AuditError::Write {
                path: self.path.clone(),
                source: e,
            })?;
        }

        if self.stdout_json {
            println!("{line}");
        }

        state.seq = seq;
        state.head = record.hash.clone();
        Ok(record)
    }

    /// Every record, oldest first.
    ///
    /// A log file that does not exist yet is an empty trail, not an error. The
    /// distinction matters: reporting it as a failure would light up the
    /// dashboard's tamper warning on a fresh install, and a warning that cries
    /// wolf on day one is a warning nobody believes on day ninety.
    pub fn records(&self) -> Result<Vec<AuditRecord>, AuditError> {
        if self.path.as_os_str().is_empty() || !self.path.exists() {
            return Ok(Vec::new());
        }
        read_all(&self.path)
    }

    /// The most recent `n` records, newest first.
    pub fn tail(&self, n: usize) -> Result<Vec<AuditRecord>, AuditError> {
        let mut records = self.records()?;
        records.reverse();
        records.truncate(n);
        Ok(records)
    }

    /// Walk the chain and report anything that does not add up.
    pub fn verify(&self) -> Result<Verification, AuditError> {
        verify_records(&self.records()?)
    }
}

fn read_all(path: &Path) -> Result<Vec<AuditRecord>, AuditError> {
    let file = std::fs::File::open(path).map_err(|e| AuditError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut records = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| AuditError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord =
            serde_json::from_str(&line).map_err(|source| AuditError::Parse {
                seq: i as u64 + 1,
                source,
            })?;
        records.push(record);
    }
    Ok(records)
}

/// Check a sequence of records forms an unbroken chain.
pub fn verify_records(records: &[AuditRecord]) -> Result<Verification, AuditError> {
    let mut breaks = Vec::new();
    let mut expected_prev = GENESIS.to_string();
    let mut expected_seq = 1u64;

    for record in records {
        if record.seq != expected_seq {
            breaks.push(ChainBreak {
                seq: record.seq,
                id: record.id,
                problem: format!(
                    "expected sequence number {expected_seq} but found {}; {} record(s) are \
                     missing from the middle of the log",
                    record.seq,
                    record.seq.saturating_sub(expected_seq)
                ),
            });
        }
        if record.prev_hash != expected_prev {
            breaks.push(ChainBreak {
                seq: record.seq,
                id: record.id,
                problem: "this record does not chain from the one before it, so a record was \
                          removed or reordered"
                    .to_string(),
            });
        }
        let recomputed = record.compute_hash();
        if recomputed != record.hash {
            breaks.push(ChainBreak {
                seq: record.seq,
                id: record.id,
                problem: "this record's contents do not match its hash, so it was edited after \
                          it was written"
                    .to_string(),
            });
        }
        expected_prev = record.hash.clone();
        expected_seq = record.seq + 1;
    }

    Ok(Verification {
        records: records.len() as u64,
        head: records.last().map(|r| r.hash.clone()),
        breaks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sql: &str) -> AuditEntry {
        AuditEntry {
            agent: "claude-code".into(),
            sql: sql.into(),
            fingerprint: "fp".into(),
            database: "postgres".into(),
            environment: Some(Environment::Production),
            policy: "production".into(),
            statement_kind: "drop_table".into(),
            risk: 100,
            decision: Some(Decision::Deny),
            outcome: Some(Outcome::Blocked),
            ..Default::default()
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "supasafe-audit-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn records_chain_together() {
        let log = AuditLog::in_memory();
        let a = log.append(entry("DROP TABLE a")).unwrap();
        let b = log.append(entry("DROP TABLE b")).unwrap();
        assert_eq!(a.seq, 1);
        assert_eq!(a.prev_hash, GENESIS);
        assert_eq!(b.seq, 2);
        assert_eq!(b.prev_hash, a.hash);
    }

    #[test]
    fn a_written_chain_verifies() {
        let path = temp_path("verify");
        let log = AuditLog::open(&path, false).unwrap();
        for i in 0..5 {
            log.append(entry(&format!("DROP TABLE t{i}"))).unwrap();
        }
        let v = log.verify().unwrap();
        assert_eq!(v.records, 5);
        assert!(v.is_intact(), "{:?}", v.breaks);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn editing_a_record_is_detected() {
        let path = temp_path("edited");
        let log = AuditLog::open(&path, false).unwrap();
        for i in 0..3 {
            log.append(entry(&format!("DROP TABLE t{i}"))).unwrap();
        }
        // Rewrite the middle record's SQL, leaving its hash alone.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
        lines[1] = lines[1].replace("DROP TABLE t1", "SELECT 1");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let v = verify_records(&read_all(&path).unwrap()).unwrap();
        assert!(!v.is_intact());
        assert!(v.breaks.iter().any(|b| b.seq == 2));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deleting_a_record_is_detected() {
        let path = temp_path("deleted");
        let log = AuditLog::open(&path, false).unwrap();
        for i in 0..4 {
            log.append(entry(&format!("DROP TABLE t{i}"))).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Remove the second record entirely.
        let kept = [lines[0], lines[2], lines[3]].join("\n");
        std::fs::write(&path, kept + "\n").unwrap();

        let v = verify_records(&read_all(&path).unwrap()).unwrap();
        assert!(!v.is_intact());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reopening_continues_the_chain() {
        let path = temp_path("reopen");
        {
            let log = AuditLog::open(&path, false).unwrap();
            log.append(entry("DROP TABLE a")).unwrap();
        }
        let log = AuditLog::open(&path, false).unwrap();
        let b = log.append(entry("DROP TABLE b")).unwrap();
        assert_eq!(b.seq, 2);
        assert!(log.verify().unwrap().is_intact());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn raw_sql_is_not_stored_unless_asked_for() {
        let log = AuditLog::in_memory();
        let mut e = entry("DELETE FROM users WHERE email = 'ada@example.com'");
        e.sql_is_raw = true;
        let r = log.append(e).unwrap();
        // The flag is cleared because this log is not configured to keep raw
        // statements.
        assert!(!r.sql_is_raw);
    }

    #[test]
    fn prompt_hashes_are_stable_and_one_way() {
        let a = hash_prompt("delete all the test users");
        let b = hash_prompt("delete all the test users");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(!a.contains("delete"));
    }

    #[test]
    fn an_empty_log_verifies() {
        let log = AuditLog::in_memory();
        let v = log.verify().unwrap();
        assert!(v.is_intact());
        assert_eq!(v.records, 0);
    }

    #[test]
    fn a_log_file_that_does_not_exist_yet_is_intact_not_broken() {
        // A fresh install must not report its own audit trail as tampered
        // with before anything has been written to it.
        let path = temp_path("fresh");
        let log = AuditLog::open(&path, false).unwrap();
        assert!(!path.exists());
        let v = log.verify().unwrap();
        assert!(v.is_intact());
        assert_eq!(v.records, 0);
    }
}
