//! The semantic model SupaSafe builds for each statement.

use serde::{Deserialize, Serialize};

use crate::kind::{Category, StatementKind};
use crate::objects::{Access, ObjectRef};
use crate::predicate::{PredicateAnalysis, Selectivity};

/// Boolean properties extracted from the AST that policies and the risk engine
/// care about. Every one of these has been the root cause of a real outage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Flags {
    /// `CASCADE` was specified. The blast radius extends to dependent objects
    /// the statement does not name.
    pub cascade: bool,
    /// `IF EXISTS` / `IF NOT EXISTS`.
    pub if_exists: bool,
    /// `OR REPLACE`. Silently overwrites an existing definition.
    pub or_replace: bool,
    /// `CONCURRENTLY`. Avoids a blocking lock.
    pub concurrently: bool,
    /// `ONLY`, which excludes inheritance children.
    pub only: bool,

    /// ALTER TABLE ... DROP COLUMN. Data loss with no undo.
    pub drops_column: bool,
    /// ALTER TABLE ... DROP CONSTRAINT.
    pub drops_constraint: bool,
    /// ALTER TABLE ... ALTER COLUMN ... TYPE. Rewrites the table under an
    /// ACCESS EXCLUSIVE lock and can fail halfway on a large table.
    pub changes_column_type: bool,
    /// ALTER TABLE ... ALTER COLUMN ... SET NOT NULL.
    pub sets_not_null: bool,
    /// ALTER ... OWNER TO. Changes who controls the object.
    pub changes_owner: bool,
    /// Adds a column.
    pub adds_column: bool,
    /// Renames an object or column. Breaks every client still using the old
    /// name, and is not detectable by a diff of the data.
    pub renames: bool,

    /// DISABLE ROW LEVEL SECURITY, or dropping an RLS policy. On Supabase this
    /// exposes every row of a table to the anon key.
    pub weakens_rls: bool,
    /// ENABLE / FORCE ROW LEVEL SECURITY.
    pub strengthens_rls: bool,
    /// DISABLE TRIGGER. Silently turns off audit and integrity logic.
    pub disables_trigger: bool,

    /// Grants or sets SUPERUSER, BYPASSRLS, REPLICATION or CREATEROLE.
    pub grants_elevated_role: bool,
    /// `GRANT ALL`.
    pub grants_all: bool,
    /// Grantee is PUBLIC, `anon` or `authenticated`: every caller gets it.
    pub grants_to_public: bool,

    /// COPY ... TO/FROM PROGRAM. Command execution on the database host.
    pub copy_program: bool,
    /// COPY ... TO/FROM a server-side file path.
    pub copy_file: bool,

    /// SECURITY DEFINER function. Runs with the owner's rights and bypasses
    /// RLS unless it is written very carefully.
    pub security_definer: bool,
    /// Body is opaque to static analysis (DO block, dynamic EXECUTE, procedure
    /// body). SupaSafe cannot see what it will run.
    pub opaque_body: bool,
    /// The opaque body contains destructive keywords.
    pub opaque_body_is_destructive: bool,

    /// `RETURNING`, which makes a write also a read.
    pub returning: bool,
    /// Statement touches more than one table.
    pub multi_table: bool,
    /// SELECT ... FOR UPDATE / FOR SHARE: a read that takes row locks.
    pub locking_read: bool,
    /// SELECT ... INTO, which creates a table as a side effect of a read.
    pub select_into: bool,
    /// The statement could not be parsed into an AST and was classified from
    /// the token stream instead.
    pub unparsed: bool,
}

impl Flags {
    /// Names of the flags that are set, for compact display and policy
    /// matching.
    pub fn active(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        macro_rules! push {
            ($($f:ident => $n:literal),* $(,)?) => {
                $( if self.$f { v.push($n); } )*
            };
        }
        push! {
            cascade => "cascade",
            if_exists => "if_exists",
            or_replace => "or_replace",
            concurrently => "concurrently",
            only => "only",
            drops_column => "drops_column",
            drops_constraint => "drops_constraint",
            changes_column_type => "changes_column_type",
            sets_not_null => "sets_not_null",
            changes_owner => "changes_owner",
            adds_column => "adds_column",
            renames => "renames",
            weakens_rls => "weakens_rls",
            strengthens_rls => "strengthens_rls",
            disables_trigger => "disables_trigger",
            grants_elevated_role => "grants_elevated_role",
            grants_all => "grants_all",
            grants_to_public => "grants_to_public",
            copy_program => "copy_program",
            copy_file => "copy_file",
            security_definer => "security_definer",
            opaque_body => "opaque_body",
            opaque_body_is_destructive => "opaque_body_is_destructive",
            returning => "returning",
            multi_table => "multi_table",
            locking_read => "locking_read",
            select_into => "select_into",
            unparsed => "unparsed",
        }
        v
    }

    /// Look a flag up by the name used in policy files.
    pub fn get(&self, name: &str) -> bool {
        self.active().contains(&name)
    }
}

/// One analysed statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementAnalysis {
    /// Position within the batch the client sent.
    pub index: usize,
    pub kind: StatementKind,
    /// The statement text exactly as received.
    pub sql: String,
    /// The statement with every literal replaced by `?`.
    pub normalized: String,
    /// Objects the statement touches.
    pub objects: Vec<ObjectRef>,
    /// Row filter analysis, for statements that have one.
    pub predicate: PredicateAnalysis,
    /// Explicit row limit, when the statement carries one.
    pub limit: Option<u64>,
    pub flags: Flags,
    /// False when the AST parser rejected the statement and SupaSafe fell back
    /// to lexical classification.
    pub parsed: bool,
    /// Why the AST parser rejected it.
    pub parse_error: Option<String>,
    /// Human readable observations attached during analysis.
    pub notes: Vec<String>,
}

impl StatementAnalysis {
    pub fn category(&self) -> Category {
        self.kind.category()
    }

    /// Objects the statement modifies, ignoring the ones it only reads.
    pub fn mutated_objects(&self) -> Vec<&ObjectRef> {
        self.objects
            .iter()
            .filter(|o| o.access.is_mutating())
            .collect()
    }

    /// Objects the statement can destroy data in.
    pub fn destroyed_objects(&self) -> Vec<&ObjectRef> {
        self.objects
            .iter()
            .filter(|o| o.access.is_lossy())
            .collect()
    }

    /// Objects on a protected managed surface (Supabase `auth`, `storage`,
    /// PostgreSQL catalogs, and so on) that this statement would modify.
    pub fn protected_objects(&self) -> Vec<&ObjectRef> {
        self.objects
            .iter()
            .filter(|o| o.is_protected() && o.access.is_mutating())
            .collect()
    }

    /// The primary object, used for one-line summaries.
    pub fn primary_object(&self) -> Option<&ObjectRef> {
        self.objects
            .iter()
            .max_by_key(|o| (o.access.is_lossy(), o.access.is_mutating()))
    }

    /// A write with no effective row filter: the shape behind almost every
    /// "the agent deleted the whole table" incident.
    pub fn is_unfiltered_write(&self) -> bool {
        matches!(self.kind, StatementKind::Update | StatementKind::Delete)
            && self.predicate.is_unfiltered()
            && self.limit.is_none()
    }

    /// True when the statement can lose data that is not recoverable from the
    /// statement text itself.
    pub fn is_data_destructive(&self) -> bool {
        self.kind.is_destructive() || self.flags.drops_column
    }

    /// Estimated share of the target table affected.
    pub fn selectivity(&self) -> Selectivity {
        self.predicate.selectivity
    }

    /// One line describing what this statement does, for approval cards.
    pub fn describe(&self) -> String {
        let target = self
            .primary_object()
            .map(|o| o.as_written())
            .unwrap_or_else(|| "the database".to_string());
        match self.kind {
            StatementKind::Delete if self.predicate.is_unfiltered() => {
                format!("delete every row from {target}")
            }
            StatementKind::Update if self.predicate.is_unfiltered() => {
                format!("update every row in {target}")
            }
            StatementKind::Truncate => format!("empty {target} and reset it"),
            StatementKind::DropTable => format!("permanently remove the table {target}"),
            StatementKind::DropSchema => format!("permanently remove the schema {target}"),
            StatementKind::DropDatabase => format!("permanently remove the database {target}"),
            _ => format!("{} on {target}", self.kind.label()),
        }
    }

    fn object_summary(&self, access: Access) -> Vec<String> {
        self.objects
            .iter()
            .filter(|o| o.access == access)
            .map(|o| o.qualified())
            .collect()
    }

    /// Tables the statement writes to.
    pub fn written_tables(&self) -> Vec<String> {
        let mut v = self.object_summary(Access::Insert);
        v.extend(self.object_summary(Access::Update));
        v.extend(self.object_summary(Access::Delete));
        v.extend(self.object_summary(Access::Truncate));
        v.sort();
        v.dedup();
        v
    }
}

/// The result of analysing one client request, which may contain several
/// statements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    pub statements: Vec<StatementAnalysis>,
    /// The batch arrived wrapped in an explicit transaction.
    pub explicit_transaction: bool,
    /// The original text of the whole request.
    pub sql: String,
}

impl Batch {
    /// The highest-consequence statement in the batch, used when a single
    /// verdict must be reported for the whole request.
    pub fn dominant(&self) -> Option<&StatementAnalysis> {
        self.statements.iter().max_by_key(|s| {
            (
                s.is_data_destructive(),
                s.is_unfiltered_write(),
                !s.protected_objects().is_empty(),
                s.kind.is_schema_change(),
            )
        })
    }

    pub fn contains_destructive(&self) -> bool {
        self.statements.iter().any(|s| s.is_data_destructive())
    }

    /// Every object referenced across the batch.
    pub fn all_objects(&self) -> Vec<&ObjectRef> {
        self.statements
            .iter()
            .flat_map(|s| s.objects.iter())
            .collect()
    }

    /// True when any statement had to be classified lexically.
    pub fn has_unparsed(&self) -> bool {
        self.statements.iter().any(|s| !s.parsed)
    }
}
