//! Snapshots taken before dangerous statements.
//!
//! A recovery point is only worth having if you know it exists before you need
//! it. SupaSafe records one *before* the statement runs, names it in the
//! approval card, and writes its identifier into the audit record, so the
//! answer to "can we get back?" is on screen at the moment of the decision
//! rather than discovered afterwards.
//!
//! Three kinds, in descending order of how much they cost to take:
//!
//! * a logical dump of the affected tables, via `pg_dump`;
//! * a marker against the platform's own point-in-time recovery, which is what
//!   Supabase provides on paid plans;
//! * a plain record of the moment, when neither is available, so that at least
//!   the timestamp to recover to is written down.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use uuid::Uuid;

/// How the recovery point was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SnapshotKind {
    /// A `pg_dump` of specific tables.
    LogicalDump { tables: Vec<String>, path: PathBuf },
    /// A `pg_dump` of the whole database.
    FullDump { path: PathBuf },
    /// A marker against continuous archiving. Nothing is copied; the timestamp
    /// is the thing you recover to.
    PointInTime { note: String },
    /// Nothing was captured. Recorded so the audit trail is honest about it.
    None { reason: String },
}

impl SnapshotKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapshotKind::LogicalDump { .. } => "logical_dump",
            SnapshotKind::FullDump { .. } => "full_dump",
            SnapshotKind::PointInTime { .. } => "point_in_time",
            SnapshotKind::None { .. } => "none",
        }
    }

    /// True when data was actually copied somewhere.
    pub fn has_data(&self) -> bool {
        matches!(
            self,
            SnapshotKind::LogicalDump { .. } | SnapshotKind::FullDump { .. }
        )
    }
}

/// A recovery point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: Uuid,
    /// A short human-readable handle, e.g. `snap-2026-07-29T10-15-00Z-users`.
    pub label: String,
    pub taken_at: DateTime<Utc>,
    pub database: String,
    pub kind: SnapshotKind,
    /// Bytes on disk, for dumps.
    pub size_bytes: Option<u64>,
    /// The statement this was taken for.
    pub for_statement: String,
    /// How to use it.
    pub restore_hint: String,
}

impl Snapshot {
    /// A sentence for the approval card.
    pub fn describe(&self) -> String {
        match &self.kind {
            SnapshotKind::LogicalDump { tables, path } => format!(
                "logical dump of {} at {}",
                tables.join(", "),
                path.display()
            ),
            SnapshotKind::FullDump { path } => format!("full dump at {}", path.display()),
            SnapshotKind::PointInTime { note } => note.clone(),
            SnapshotKind::None { reason } => format!("no snapshot: {reason}"),
        }
    }
}

/// What went wrong taking a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("could not create the snapshot directory {path}: {source}")]
    Directory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not run {program}: {source}. Install the PostgreSQL client tools, or set snapshots.pg_dump_path")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("pg_dump failed: {0}")]
    DumpFailed(String),
    #[error("the snapshot did not finish within {0} seconds")]
    Timeout(u64),
}

/// Settings for taking snapshots.
#[derive(Debug, Clone)]
pub struct SnapshotSettings {
    pub directory: PathBuf,
    pub pg_dump_path: String,
    pub prefer_table_scope: bool,
    pub timeout_seconds: u64,
}

impl Default for SnapshotSettings {
    fn default() -> Self {
        Self {
            directory: PathBuf::from(".supasafe/snapshots"),
            pg_dump_path: "pg_dump".to_string(),
            prefer_table_scope: true,
            timeout_seconds: 900,
        }
    }
}

/// Takes recovery points.
#[derive(Debug, Clone)]
pub struct SnapshotManager {
    settings: SnapshotSettings,
    /// The connection string `pg_dump` is given. Held separately from the
    /// proxy's forwarding path so that snapshots need explicitly granted
    /// credentials rather than borrowing the agent's.
    connection_url: Option<String>,
}

impl SnapshotManager {
    pub fn new(settings: SnapshotSettings, connection_url: Option<String>) -> Self {
        Self {
            settings,
            connection_url,
        }
    }

    pub fn settings(&self) -> &SnapshotSettings {
        &self.settings
    }

    /// Whether this manager can actually copy data, as opposed to only
    /// recording a timestamp.
    pub fn can_dump(&self) -> bool {
        self.connection_url.is_some()
    }

    /// Take a recovery point before `statement`, covering `tables`.
    pub async fn capture(
        &self,
        database: &str,
        statement: &str,
        tables: &[String],
    ) -> Result<Snapshot, SnapshotError> {
        let taken_at = Utc::now();
        let label = format!(
            "snap-{}-{}",
            taken_at.format("%Y%m%dT%H%M%SZ"),
            tables
                .first()
                .map(|t| t.replace('.', "_"))
                .unwrap_or_else(|| "db".to_string())
        );

        let Some(url) = &self.connection_url else {
            return Ok(Snapshot {
                id: Uuid::new_v4(),
                label: label.clone(),
                taken_at,
                database: database.to_string(),
                kind: SnapshotKind::PointInTime {
                    note: format!(
                        "no dump credentials are configured, so nothing was copied. If this \
                         database has point-in-time recovery, recover to just before {}",
                        taken_at.to_rfc3339()
                    ),
                },
                size_bytes: None,
                for_statement: statement.to_string(),
                restore_hint: point_in_time_hint(taken_at),
            });
        };

        std::fs::create_dir_all(&self.settings.directory).map_err(|e| {
            SnapshotError::Directory {
                path: self.settings.directory.clone(),
                source: e,
            }
        })?;

        let path = self.settings.directory.join(format!("{label}.sql"));
        let scoped = self.settings.prefer_table_scope && !tables.is_empty();

        let mut cmd = tokio::process::Command::new(&self.settings.pg_dump_path);
        cmd.arg("--no-owner")
            .arg("--no-privileges")
            .arg("--file")
            .arg(&path);
        if scoped {
            for table in tables {
                cmd.arg("--table").arg(table);
            }
        }
        cmd.arg(url);
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());

        let child = cmd.spawn().map_err(|e| SnapshotError::Spawn {
            program: self.settings.pg_dump_path.clone(),
            source: e,
        })?;

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(self.settings.timeout_seconds),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| SnapshotError::Timeout(self.settings.timeout_seconds))?
        .map_err(|e| SnapshotError::Spawn {
            program: self.settings.pg_dump_path.clone(),
            source: e,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(SnapshotError::DumpFailed(redact_url(&stderr)));
        }

        let size_bytes = std::fs::metadata(&path).ok().map(|m| m.len());

        Ok(Snapshot {
            id: Uuid::new_v4(),
            label,
            taken_at,
            database: database.to_string(),
            kind: if scoped {
                SnapshotKind::LogicalDump {
                    tables: tables.to_vec(),
                    path: path.clone(),
                }
            } else {
                SnapshotKind::FullDump { path: path.clone() }
            },
            size_bytes,
            for_statement: statement.to_string(),
            restore_hint: format!("psql <connection> --file {}", path.display()),
        })
    }

    /// Record that no snapshot was taken, and why. Used when a policy asked
    /// for one and it could not be produced, so the reason lands in the audit
    /// trail instead of disappearing.
    pub fn unavailable(database: &str, statement: &str, reason: impl Into<String>) -> Snapshot {
        let taken_at = Utc::now();
        Snapshot {
            id: Uuid::new_v4(),
            label: format!("snap-{}-none", taken_at.format("%Y%m%dT%H%M%SZ")),
            taken_at,
            database: database.to_string(),
            kind: SnapshotKind::None {
                reason: reason.into(),
            },
            size_bytes: None,
            for_statement: statement.to_string(),
            restore_hint: point_in_time_hint(taken_at),
        }
    }

    /// Snapshots on disk, newest first.
    pub fn list(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = match std::fs::read_dir(&self.settings.directory) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().map(|e| e == "sql").unwrap_or(false))
                .collect(),
            Err(_) => Vec::new(),
        };
        files.sort();
        files.reverse();
        files
    }
}

fn point_in_time_hint(at: DateTime<Utc>) -> String {
    format!(
        "If this project has point-in-time recovery enabled, restore to just before {}. \
         On Supabase this is under Database → Backups → Point in Time.",
        at.to_rfc3339()
    )
}

/// Strip anything that looks like a connection string out of a message before
/// it reaches a log or a dashboard.
pub fn redact_url(text: &str) -> String {
    text.split_whitespace()
        .map(|word| {
            if word.contains("://") && word.contains('@') {
                "<connection string redacted>"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Tables worth capturing before a statement runs: the ones it can lose data
/// in.
pub fn tables_to_capture(stmt: &supasafe_parser::StatementAnalysis) -> Vec<String> {
    let mut tables: Vec<String> = stmt
        .objects
        .iter()
        .filter(|o| o.access.is_lossy() || o.access == supasafe_parser::Access::Update)
        .filter(|o| matches!(o.kind, supasafe_parser::ObjectKind::Table))
        .map(|o| o.qualified())
        .collect();
    tables.sort();
    tables.dedup();
    tables
}

#[cfg(test)]
mod tests {
    use super::*;
    use supasafe_parser::analyze_statement;

    #[tokio::test]
    async fn without_credentials_it_records_a_point_in_time_marker() {
        let m = SnapshotManager::new(SnapshotSettings::default(), None);
        assert!(!m.can_dump());
        let s = m
            .capture("postgres", "DROP TABLE users", &["public.users".into()])
            .await
            .unwrap();
        assert!(matches!(s.kind, SnapshotKind::PointInTime { .. }));
        assert!(!s.kind.has_data());
        assert!(s.restore_hint.contains("point-in-time"));
    }

    #[test]
    fn unavailable_snapshots_say_why() {
        let s =
            SnapshotManager::unavailable("postgres", "DROP TABLE t", "pg_dump is not installed");
        assert!(s.describe().contains("pg_dump is not installed"));
    }

    #[test]
    fn capture_targets_are_the_tables_that_lose_data() {
        let stmt = analyze_statement("DELETE FROM public.users WHERE id = 1");
        assert_eq!(tables_to_capture(&stmt), vec!["public.users".to_string()]);

        let stmt = analyze_statement("SELECT * FROM public.users");
        assert!(tables_to_capture(&stmt).is_empty());

        let stmt = analyze_statement("DELETE FROM a WHERE id IN (SELECT id FROM b)");
        // `b` is only read, so it does not need capturing.
        assert_eq!(tables_to_capture(&stmt), vec!["public.a".to_string()]);
    }

    #[test]
    fn connection_strings_never_reach_a_log() {
        let msg = "pg_dump: error: connection to postgresql://user:hunter2@db.example.com/postgres failed";
        let redacted = redact_url(msg);
        assert!(!redacted.contains("hunter2"));
        assert!(redacted.contains("redacted"));
    }

    #[tokio::test]
    async fn a_missing_pg_dump_is_a_clear_error() {
        let m = SnapshotManager::new(
            SnapshotSettings {
                pg_dump_path: "definitely-not-a-real-binary".into(),
                directory: std::env::temp_dir().join("supasafe-snap-test"),
                ..Default::default()
            },
            Some("postgresql://localhost/postgres".into()),
        );
        let err = m
            .capture("postgres", "DROP TABLE t", &["public.t".into()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("definitely-not-a-real-binary"));
    }
}
