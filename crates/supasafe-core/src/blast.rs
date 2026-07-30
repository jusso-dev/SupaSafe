//! Blast radius analysis: what this statement actually reaches.
//!
//! An agent asks to delete some rows from `users`. The honest answer is rarely
//! "some rows from users". It is "1,000 rows from users, 50,000 from orders and
//! 400,000 from order_items, under a lock that stops every other session from
//! reading the table, for roughly nine seconds, generating 60MB of WAL that
//! your read replica has to replay".
//!
//! That is the sentence a human needs before they press approve.

use serde::{Deserialize, Serialize};
use supasafe_parser::{Selectivity, StatementAnalysis, StatementKind};

use crate::catalog::{CascadeStep, CatalogSnapshot};

/// A number SupaSafe is more or less sure about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Estimate {
    /// Known exactly, e.g. from a LIMIT.
    Exact(u64),
    /// From planner statistics or a heuristic.
    Approximate(u64),
    /// No basis for an estimate.
    Unknown,
}

impl Estimate {
    pub fn value(&self) -> Option<u64> {
        match self {
            Estimate::Exact(n) | Estimate::Approximate(n) => Some(*n),
            Estimate::Unknown => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Estimate::Exact(n) => format!("{n}"),
            Estimate::Approximate(n) => format!("about {n}"),
            Estimate::Unknown => "unknown".to_string(),
        }
    }
}

/// PostgreSQL lock modes, in the order of how much they block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockMode {
    AccessShare,
    RowShare,
    RowExclusive,
    ShareUpdateExclusive,
    Share,
    ShareRowExclusive,
    Exclusive,
    AccessExclusive,
}

impl LockMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            LockMode::AccessShare => "ACCESS SHARE",
            LockMode::RowShare => "ROW SHARE",
            LockMode::RowExclusive => "ROW EXCLUSIVE",
            LockMode::ShareUpdateExclusive => "SHARE UPDATE EXCLUSIVE",
            LockMode::Share => "SHARE",
            LockMode::ShareRowExclusive => "SHARE ROW EXCLUSIVE",
            LockMode::Exclusive => "EXCLUSIVE",
            LockMode::AccessExclusive => "ACCESS EXCLUSIVE",
        }
    }

    /// What other sessions cannot do while this lock is held.
    pub fn blocks(&self) -> &'static str {
        match self {
            LockMode::AccessShare => "nothing except a concurrent ACCESS EXCLUSIVE lock",
            LockMode::RowShare | LockMode::RowExclusive => "schema changes to the table",
            LockMode::ShareUpdateExclusive => "other maintenance and schema changes",
            LockMode::Share => "all writes to the table",
            LockMode::ShareRowExclusive | LockMode::Exclusive => {
                "all writes and other readers taking row locks"
            }
            LockMode::AccessExclusive => "every other session, including plain SELECT",
        }
    }

    /// The lock a statement takes on its primary target.
    pub fn for_statement(kind: StatementKind) -> LockMode {
        use StatementKind::*;
        match kind {
            Select | Explain | Show | CopyTo | Fetch => LockMode::AccessShare,
            Insert | Update | Delete | Merge | CopyFrom => LockMode::RowExclusive,
            CreateIndex => LockMode::Share,
            Vacuum | Analyze => LockMode::ShareUpdateExclusive,
            Truncate | DropTable | DropSchema | DropDatabase | AlterTable | Cluster | Reindex
            | DropView | DropMaterializedView | DropIndex => LockMode::AccessExclusive,
            Lock => LockMode::AccessExclusive,
            _ => LockMode::AccessShare,
        }
    }
}

/// What the statement does to one table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TableImpact {
    pub table: String,
    pub access: String,
    /// Rows currently in the table, when known.
    pub current_rows: Estimate,
    /// Rows the statement is expected to change.
    pub affected_rows: Estimate,
    /// Rows expected to remain afterwards.
    pub rows_after: Estimate,
    pub lock: LockMode,
    pub indexes: u32,
    /// Row level security is on for this table.
    pub rls_enabled: bool,
    /// Triggers that will fire.
    pub triggers: u32,
}

/// The full picture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Total rows the statement is expected to change.
    pub rows_affected: Estimate,
    pub tables: Vec<TableImpact>,
    /// Tables reached through `ON DELETE CASCADE` that the statement never
    /// mentions.
    pub cascades: Vec<CascadeStep>,
    /// Rows in cascaded tables that would also go.
    pub cascade_rows: Estimate,
    /// Indexes that have to be maintained or rebuilt.
    pub indexes_touched: u32,
    /// Foreign key constraints that will be checked or enforced.
    pub foreign_keys_checked: usize,
    /// The heaviest lock the statement takes.
    pub heaviest_lock: LockMode,
    /// Bytes of write-ahead log the statement is expected to generate. This is
    /// what a replica has to replay and what a backup has to store.
    pub wal_bytes: Estimate,
    /// Change in on-disk size. Negative values are reclaimed space, though
    /// PostgreSQL only returns it to the filesystem after a VACUUM FULL.
    pub disk_delta_bytes: i64,
    /// How long the statement is expected to run, in milliseconds.
    pub duration_ms: Estimate,
    /// The statement changes data on a table that is logically replicated.
    pub affects_replication: bool,
    /// Plain sentences describing what a human should be worried about.
    pub warnings: Vec<String>,
    /// True when no catalogue was available and these numbers are structural
    /// guesses rather than measurements.
    pub estimated_without_catalog: bool,
}

impl BlastRadius {
    /// A one-line summary for a notification or a CLI line.
    pub fn summary(&self) -> String {
        let rows = match self.rows_affected {
            Estimate::Unknown => "an unknown number of rows".to_string(),
            e => format!("{} rows", e.describe()),
        };
        let tables = self.tables.len();
        let mut s = format!(
            "{rows} across {tables} table{}",
            if tables == 1 { "" } else { "s" }
        );
        if !self.cascades.is_empty() {
            s.push_str(&format!(", cascading into {} more", self.cascades.len()));
        }
        if self.heaviest_lock >= LockMode::Share {
            s.push_str(&format!(", holding a {} lock", self.heaviest_lock.as_str()));
        }
        s
    }
}

/// Average bytes of WAL per changed row. A rough figure, but the order of
/// magnitude is what matters when deciding whether a statement will flood a
/// replica.
const WAL_BYTES_PER_ROW: u64 = 120;
/// Rows per millisecond for a straightforward write. Deliberately optimistic,
/// so a duration estimate that already looks bad really is bad.
const ROWS_PER_MS: u64 = 500;

/// Work out the blast radius of a statement.
pub fn analyze(stmt: &StatementAnalysis, catalog: Option<&CatalogSnapshot>) -> BlastRadius {
    let mut tables = Vec::new();
    let mut warnings = Vec::new();
    let mut cascades = Vec::new();
    let mut indexes_touched = 0u32;
    let mut foreign_keys_checked = 0usize;
    // Rows are summed across tables, but a single table SupaSafe cannot
    // estimate makes the total unknown rather than merely smaller. Reporting a
    // partial sum as if it were the whole would understate the blast radius,
    // which is the one direction that must never happen.
    let mut affected_sum: u64 = 0;
    let mut any_unknown = false;
    let mut affects_replication = false;
    let mut disk_delta: i64 = 0;

    let lock = LockMode::for_statement(stmt.kind);

    for obj in &stmt.objects {
        if !matches!(obj.kind, supasafe_parser::ObjectKind::Table) {
            continue;
        }
        let qualified = obj.qualified();
        let stats = catalog.and_then(|c| c.table(&qualified));

        let current_rows = match stats {
            Some(s) => Estimate::Approximate(s.estimated_rows),
            None => Estimate::Unknown,
        };

        let affected = affected_rows(stmt, obj.access, current_rows);
        let rows_after = rows_after(stmt, obj.access, current_rows, affected);

        match affected.value() {
            Some(n) => affected_sum = affected_sum.saturating_add(n),
            None if obj.access.is_mutating() => any_unknown = true,
            None => {}
        }

        if obj.access.is_mutating() {
            if let Some(s) = stats {
                indexes_touched += s.index_count;
                if s.replicated {
                    affects_replication = true;
                }
                if s.trigger_count > 0 {
                    warnings.push(format!(
                        "{qualified} has {} trigger(s) that will fire for every affected row",
                        s.trigger_count
                    ));
                }
                if s.rls_enabled && s.policy_count == 0 {
                    warnings.push(format!(
                        "{qualified} has row level security enabled but no policies, so it is \
                         currently readable by nobody except its owner"
                    ));
                }
            }
        }

        // Deletions and drops free space; inserts consume it.
        if let (Some(s), Some(n)) = (stats, affected.value()) {
            let bytes_per_row = if s.estimated_rows > 0 {
                (s.total_bytes / s.estimated_rows.max(1)) as i64
            } else {
                0
            };
            disk_delta += match obj.access {
                supasafe_parser::Access::Insert => bytes_per_row * n as i64,
                supasafe_parser::Access::Delete | supasafe_parser::Access::Truncate => {
                    -(bytes_per_row * n as i64)
                }
                supasafe_parser::Access::Drop => -(s.total_bytes as i64),
                // An UPDATE writes a new row version and leaves the old one
                // behind until VACUUM.
                supasafe_parser::Access::Update => bytes_per_row * n as i64,
                _ => 0,
            };
        }

        if let Some(c) = catalog {
            if obj.access.is_lossy() {
                let steps = c.cascade_from(&qualified);
                if !steps.is_empty() {
                    if stmt.flags.cascade || stmt.kind == StatementKind::Delete {
                        cascades.extend(steps.iter().cloned());
                    } else {
                        // Without CASCADE, those same constraints will refuse
                        // the statement instead.
                        warnings.push(format!(
                            "{} table(s) have foreign keys to {qualified}; without CASCADE this \
                             statement will fail rather than run",
                            steps.len()
                        ));
                    }
                }
                foreign_keys_checked += c.dependents(&qualified).len();
            }
        }

        tables.push(TableImpact {
            table: qualified,
            access: obj.access.as_str().to_string(),
            current_rows,
            affected_rows: affected,
            rows_after,
            lock: if obj.access.is_mutating() {
                lock
            } else {
                LockMode::AccessShare
            },
            indexes: stats.map(|s| s.index_count).unwrap_or(0),
            rls_enabled: stats.map(|s| s.rls_enabled).unwrap_or(false),
            triggers: stats.map(|s| s.trigger_count).unwrap_or(0),
        });
    }

    cascades.sort_by_key(|s| (s.depth, s.table.clone()));
    cascades.dedup_by_key(|s| s.table.clone());

    let cascade_rows = match catalog {
        Some(c) if !cascades.is_empty() => Estimate::Approximate(
            cascades
                .iter()
                .filter_map(|s| c.rows(&s.table))
                .sum::<u64>(),
        ),
        _ => Estimate::Unknown,
    };

    let total_affected = if any_unknown {
        None
    } else {
        Some(affected_sum)
    };

    // Cascaded rows are still rows this statement destroys.
    let rows_affected = match (total_affected, cascade_rows.value()) {
        (Some(a), Some(b)) => Estimate::Approximate(a + b),
        (Some(a), None) => Estimate::Approximate(a),
        (None, _) => Estimate::Unknown,
    };

    let wal_bytes = match rows_affected.value() {
        // TRUNCATE is the exception that makes it dangerous: it does not write
        // per-row WAL, which is exactly why it cannot be undone row by row.
        Some(_) if stmt.kind == StatementKind::Truncate => Estimate::Approximate(0),
        Some(n) => Estimate::Approximate(n * WAL_BYTES_PER_ROW),
        None => Estimate::Unknown,
    };

    let duration_ms = match rows_affected.value() {
        Some(n) => Estimate::Approximate((n / ROWS_PER_MS).max(1)),
        None => Estimate::Unknown,
    };

    // --- warnings that do not need a catalogue ----------------------------
    if lock >= LockMode::Share {
        warnings.push(format!(
            "this statement takes an {} lock, which blocks {}",
            lock.as_str(),
            lock.blocks()
        ));
    }
    if stmt.kind == StatementKind::Truncate {
        warnings.push(
            "TRUNCATE does not write per-row WAL, so the rows cannot be recovered by \
             point-in-time recovery to a moment after the statement"
                .to_string(),
        );
    }
    if stmt.flags.cascade {
        warnings.push(
            "CASCADE means objects the statement does not name will also be dropped".to_string(),
        );
    }
    if !cascades.is_empty() {
        warnings.push(format!(
            "{} table(s) will be modified through ON DELETE CASCADE without appearing in the \
             statement: {}",
            cascades.len(),
            cascades
                .iter()
                .map(|s| s.table.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(rows) = rows_affected.value() {
        if rows > 1_000_000 {
            warnings.push(
                "a statement of this size will hold its locks for a long time and can push a \
                 read replica behind"
                    .to_string(),
            );
        }
    }
    if affects_replication {
        warnings.push(
            "this table is published for logical replication, so the change will propagate to \
             every subscriber"
                .to_string(),
        );
    }
    if catalog.is_none() && (stmt.kind.is_write() || stmt.is_data_destructive()) {
        warnings.push(
            "no read-only introspection connection is configured, so row counts and cascade \
             paths could not be measured; set proxy.introspection_url to get real numbers"
                .to_string(),
        );
    }

    BlastRadius {
        rows_affected,
        tables,
        cascades,
        cascade_rows,
        indexes_touched,
        foreign_keys_checked,
        heaviest_lock: lock,
        wal_bytes,
        disk_delta_bytes: disk_delta,
        duration_ms,
        affects_replication,
        warnings,
        estimated_without_catalog: catalog.is_none(),
    }
}

/// How many rows a statement will change in one table.
fn affected_rows(
    stmt: &StatementAnalysis,
    access: supasafe_parser::Access,
    current: Estimate,
) -> Estimate {
    use supasafe_parser::Access::*;

    if !access.is_mutating() {
        return Estimate::Exact(0);
    }

    // An explicit LIMIT is the one thing we know exactly.
    if let Some(limit) = stmt.limit {
        return Estimate::Exact(limit);
    }

    match access {
        Insert => Estimate::Approximate(1),
        Truncate | Drop => current,
        Update | Delete => match stmt.selectivity() {
            Selectivity::Unbounded => current,
            Selectivity::SingleRow => Estimate::Approximate(1),
            Selectivity::Narrow => match current.value() {
                // A bounded set: assume a small share of the table.
                Some(n) => Estimate::Approximate((n / 100).clamp(1, 1_000)),
                None => Estimate::Unknown,
            },
            Selectivity::Broad => match current.value() {
                // With no statistics on the predicate, PostgreSQL's own
                // default assumption for an unknown equality is around 0.5%;
                // a tenth of the table is a deliberately pessimistic stand-in
                // for "we do not know".
                Some(n) => Estimate::Approximate((n / 10).max(1)),
                None => Estimate::Unknown,
            },
        },
        _ => Estimate::Unknown,
    }
}

fn rows_after(
    stmt: &StatementAnalysis,
    access: supasafe_parser::Access,
    current: Estimate,
    affected: Estimate,
) -> Estimate {
    use supasafe_parser::Access::*;
    let (Some(current), Some(affected)) = (current.value(), affected.value()) else {
        return Estimate::Unknown;
    };
    match access {
        Delete | Truncate => Estimate::Approximate(current.saturating_sub(affected)),
        Drop => Estimate::Exact(0),
        Insert => Estimate::Approximate(current + affected),
        // An UPDATE changes rows without changing how many there are.
        Update => Estimate::Approximate(current),
        _ => {
            let _ = stmt;
            Estimate::Approximate(current)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{ForeignKey, OnDelete, TableStats};
    use supasafe_parser::analyze_statement;

    fn catalog() -> CatalogSnapshot {
        let mut c = CatalogSnapshot::default();
        for (name, rows, indexes) in [
            ("public.users", 1_000u64, 3u32),
            ("public.orders", 50_000, 4),
            ("public.order_items", 400_000, 2),
        ] {
            let (schema, table) = name.split_once('.').unwrap();
            c.insert_table(TableStats {
                schema: schema.into(),
                name: table.into(),
                estimated_rows: rows,
                total_bytes: rows * 200,
                index_count: indexes,
                rls_enabled: false,
                policy_count: 0,
                trigger_count: 0,
                replicated: false,
            });
        }
        c.foreign_keys = vec![
            ForeignKey {
                name: "orders_user_fk".into(),
                child: "public.orders".into(),
                parent: "public.users".into(),
                on_delete: OnDelete::Cascade,
            },
            ForeignKey {
                name: "items_order_fk".into(),
                child: "public.order_items".into(),
                parent: "public.orders".into(),
                on_delete: OnDelete::Cascade,
            },
        ];
        c
    }

    #[test]
    fn a_read_affects_nothing() {
        let b = analyze(&analyze_statement("SELECT * FROM users"), Some(&catalog()));
        assert_eq!(b.rows_affected.value(), Some(0));
        assert_eq!(b.heaviest_lock, LockMode::AccessShare);
    }

    #[test]
    fn an_unfiltered_delete_takes_the_whole_table_and_its_children() {
        let b = analyze(&analyze_statement("DELETE FROM users"), Some(&catalog()));
        // 1,000 users, plus 50,000 orders and 400,000 items through cascade.
        assert_eq!(b.rows_affected.value(), Some(451_000));
        assert_eq!(b.cascades.len(), 2);
        assert!(b.warnings.iter().any(|w| w.contains("ON DELETE CASCADE")));
    }

    #[test]
    fn a_key_delete_takes_one_row() {
        let b = analyze(
            &analyze_statement("DELETE FROM users WHERE id = 1"),
            Some(&catalog()),
        );
        assert_eq!(b.tables[0].affected_rows.value(), Some(1));
    }

    #[test]
    fn rows_after_is_reported() {
        let b = analyze(&analyze_statement("DELETE FROM users"), Some(&catalog()));
        let users = b.tables.iter().find(|t| t.table == "public.users").unwrap();
        assert_eq!(users.current_rows.value(), Some(1_000));
        assert_eq!(users.rows_after.value(), Some(0));
    }

    #[test]
    fn truncate_generates_no_wal_which_is_the_problem() {
        let b = analyze(
            &analyze_statement("TRUNCATE TABLE public.orders"),
            Some(&catalog()),
        );
        assert_eq!(b.wal_bytes.value(), Some(0));
        assert!(b.warnings.iter().any(|w| w.contains("point-in-time")));
    }

    #[test]
    fn heavy_locks_are_called_out() {
        let b = analyze(&analyze_statement("DROP TABLE users"), Some(&catalog()));
        assert_eq!(b.heaviest_lock, LockMode::AccessExclusive);
        assert!(b.warnings.iter().any(|w| w.contains("ACCESS EXCLUSIVE")));
    }

    #[test]
    fn without_a_catalog_it_says_so() {
        let b = analyze(&analyze_statement("DELETE FROM users"), None);
        assert!(b.estimated_without_catalog);
        assert_eq!(b.rows_affected, Estimate::Unknown);
        assert!(b.warnings.iter().any(|w| w.contains("introspection")));
    }

    #[test]
    fn a_limit_is_exact() {
        let b = analyze(
            &analyze_statement("DELETE FROM users WHERE status = 'x' LIMIT 10"),
            Some(&catalog()),
        );
        assert_eq!(b.tables[0].affected_rows, Estimate::Exact(10));
    }

    #[test]
    fn disk_is_reclaimed_by_deletes_and_consumed_by_inserts() {
        let del = analyze(&analyze_statement("DELETE FROM users"), Some(&catalog()));
        assert!(del.disk_delta_bytes < 0);
        let ins = analyze(
            &analyze_statement("INSERT INTO users (id) VALUES (1)"),
            Some(&catalog()),
        );
        assert!(ins.disk_delta_bytes > 0);
    }

    #[test]
    fn a_summary_reads_like_a_sentence() {
        let b = analyze(&analyze_statement("DELETE FROM users"), Some(&catalog()));
        let s = b.summary();
        assert!(s.contains("rows"), "{s}");
        assert!(s.contains("cascading"), "{s}");
    }
}
