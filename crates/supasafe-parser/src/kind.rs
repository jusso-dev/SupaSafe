//! The statement taxonomy SupaSafe reasons about.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Broad families used by policies that want to talk about "all DDL" rather
/// than enumerating forty statement kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Reads no rows change.
    Read,
    /// Data manipulation: INSERT/UPDATE/DELETE/MERGE/COPY FROM.
    Write,
    /// Schema changes.
    Ddl,
    /// Permissions and ownership.
    Dcl,
    /// VACUUM, ANALYZE, REINDEX, CLUSTER.
    Maintenance,
    /// BEGIN/COMMIT/ROLLBACK/SAVEPOINT.
    Transaction,
    /// SET/SHOW/DISCARD/PREPARE and other session-scoped statements.
    Session,
    /// Executes an opaque body: CALL, DO.
    Execute,
    /// Anything SupaSafe could not classify.
    Unknown,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Read => "read",
            Category::Write => "write",
            Category::Ddl => "ddl",
            Category::Dcl => "dcl",
            Category::Maintenance => "maintenance",
            Category::Transaction => "transaction",
            Category::Session => "session",
            Category::Execute => "execute",
            Category::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

macro_rules! statement_kinds {
    ($( $variant:ident => ($id:literal, $label:literal, $cat:ident) ),* $(,)?) => {
        /// Every statement shape SupaSafe understands.
        ///
        /// Policy rules match on the snake_case identifier, so these names are
        /// part of the public configuration surface and must stay stable.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum StatementKind {
            $( $variant, )*
        }

        impl StatementKind {
            /// Stable identifier used in policy files and the audit log.
            pub fn as_str(&self) -> &'static str {
                match self { $( StatementKind::$variant => $id, )* }
            }

            /// Human readable name for dashboards and CLI output.
            pub fn label(&self) -> &'static str {
                match self { $( StatementKind::$variant => $label, )* }
            }

            /// Family this statement belongs to.
            pub fn category(&self) -> Category {
                match self { $( StatementKind::$variant => Category::$cat, )* }
            }

            /// Parse a policy-file identifier back into a kind.
            ///
            /// Deliberately not `FromStr`: an unrecognised identifier is a
            /// miss, not an error, and callers branch on `Option`.
            #[allow(clippy::should_implement_trait)]
            pub fn from_str(s: &str) -> Option<Self> {
                match s { $( $id => Some(StatementKind::$variant), )* _ => None }
            }

            /// Every kind, for `supasafe policy explain` and docs generation.
            pub fn all() -> &'static [StatementKind] {
                &[ $( StatementKind::$variant, )* ]
            }
        }
    };
}

statement_kinds! {
    // ---- reads -------------------------------------------------------
    Select              => ("select", "SELECT", Read),
    Explain             => ("explain", "EXPLAIN", Read),
    Show                => ("show", "SHOW", Read),

    // ---- writes ------------------------------------------------------
    Insert              => ("insert", "INSERT", Write),
    Update              => ("update", "UPDATE", Write),
    Delete              => ("delete", "DELETE", Write),
    Merge               => ("merge", "MERGE", Write),
    Truncate            => ("truncate", "TRUNCATE", Write),
    CopyFrom            => ("copy_from", "COPY ... FROM", Write),
    CopyTo              => ("copy_to", "COPY ... TO", Read),

    // ---- DDL: create -------------------------------------------------
    CreateTable         => ("create_table", "CREATE TABLE", Ddl),
    CreateSchema        => ("create_schema", "CREATE SCHEMA", Ddl),
    CreateDatabase      => ("create_database", "CREATE DATABASE", Ddl),
    CreateIndex         => ("create_index", "CREATE INDEX", Ddl),
    CreateView          => ("create_view", "CREATE VIEW", Ddl),
    CreateMaterializedView => ("create_materialized_view", "CREATE MATERIALIZED VIEW", Ddl),
    CreateFunction      => ("create_function", "CREATE FUNCTION", Ddl),
    CreateProcedure     => ("create_procedure", "CREATE PROCEDURE", Ddl),
    CreateTrigger       => ("create_trigger", "CREATE TRIGGER", Ddl),
    CreatePolicy        => ("create_policy", "CREATE POLICY", Ddl),
    CreateExtension     => ("create_extension", "CREATE EXTENSION", Ddl),
    CreateRole          => ("create_role", "CREATE ROLE", Dcl),
    CreateType          => ("create_type", "CREATE TYPE", Ddl),
    CreateSequence      => ("create_sequence", "CREATE SEQUENCE", Ddl),
    CreateDomain        => ("create_domain", "CREATE DOMAIN", Ddl),
    CreateOther         => ("create_other", "CREATE", Ddl),

    // ---- DDL: alter --------------------------------------------------
    AlterTable          => ("alter_table", "ALTER TABLE", Ddl),
    AlterSchema         => ("alter_schema", "ALTER SCHEMA", Ddl),
    AlterIndex          => ("alter_index", "ALTER INDEX", Ddl),
    AlterView           => ("alter_view", "ALTER VIEW", Ddl),
    AlterFunction       => ("alter_function", "ALTER FUNCTION", Ddl),
    AlterType           => ("alter_type", "ALTER TYPE", Ddl),
    AlterPolicy         => ("alter_policy", "ALTER POLICY", Ddl),
    AlterRole           => ("alter_role", "ALTER ROLE", Dcl),
    AlterOther          => ("alter_other", "ALTER", Ddl),

    // ---- DDL: drop ---------------------------------------------------
    DropTable           => ("drop_table", "DROP TABLE", Ddl),
    DropSchema          => ("drop_schema", "DROP SCHEMA", Ddl),
    DropDatabase        => ("drop_database", "DROP DATABASE", Ddl),
    DropIndex           => ("drop_index", "DROP INDEX", Ddl),
    DropView            => ("drop_view", "DROP VIEW", Ddl),
    DropMaterializedView => ("drop_materialized_view", "DROP MATERIALIZED VIEW", Ddl),
    DropFunction        => ("drop_function", "DROP FUNCTION", Ddl),
    DropProcedure       => ("drop_procedure", "DROP PROCEDURE", Ddl),
    DropTrigger         => ("drop_trigger", "DROP TRIGGER", Ddl),
    DropPolicy          => ("drop_policy", "DROP POLICY", Ddl),
    DropExtension       => ("drop_extension", "DROP EXTENSION", Ddl),
    DropType            => ("drop_type", "DROP TYPE", Ddl),
    DropSequence        => ("drop_sequence", "DROP SEQUENCE", Ddl),
    DropRole            => ("drop_role", "DROP ROLE", Dcl),
    DropOther           => ("drop_other", "DROP", Ddl),

    // ---- DCL ---------------------------------------------------------
    Grant               => ("grant", "GRANT", Dcl),
    Revoke              => ("revoke", "REVOKE", Dcl),
    Deny                => ("deny", "DENY", Dcl),
    Comment             => ("comment", "COMMENT ON", Ddl),

    // ---- maintenance -------------------------------------------------
    Vacuum              => ("vacuum", "VACUUM", Maintenance),
    Analyze             => ("analyze", "ANALYZE", Maintenance),
    Reindex             => ("reindex", "REINDEX", Maintenance),
    Cluster             => ("cluster", "CLUSTER", Maintenance),
    Checkpoint          => ("checkpoint", "CHECKPOINT", Maintenance),

    // ---- execution ---------------------------------------------------
    Call                => ("call", "CALL", Execute),
    DoBlock             => ("do_block", "DO", Execute),
    Execute             => ("execute", "EXECUTE", Execute),

    // ---- transactions ------------------------------------------------
    Begin               => ("begin", "BEGIN", Transaction),
    Commit              => ("commit", "COMMIT", Transaction),
    Rollback            => ("rollback", "ROLLBACK", Transaction),
    Savepoint           => ("savepoint", "SAVEPOINT", Transaction),
    ReleaseSavepoint    => ("release_savepoint", "RELEASE SAVEPOINT", Transaction),

    // ---- session -----------------------------------------------------
    Set                 => ("set", "SET", Session),
    Reset               => ("reset", "RESET", Session),
    Discard             => ("discard", "DISCARD", Session),
    Prepare             => ("prepare", "PREPARE", Session),
    Deallocate          => ("deallocate", "DEALLOCATE", Session),
    Declare             => ("declare", "DECLARE", Session),
    Fetch               => ("fetch", "FETCH", Read),
    Close               => ("close", "CLOSE", Session),
    Listen              => ("listen", "LISTEN", Session),
    Unlisten            => ("unlisten", "UNLISTEN", Session),
    Notify              => ("notify", "NOTIFY", Session),
    Lock                => ("lock", "LOCK TABLE", Session),
    Use                 => ("use", "USE", Session),

    // ---- fallback ----------------------------------------------------
    Unknown             => ("unknown", "UNKNOWN", Unknown),
}

impl StatementKind {
    /// Statements that destroy data or schema objects outright. These are the
    /// ones SupaSafe exists to stop.
    pub fn is_destructive(&self) -> bool {
        use StatementKind::*;
        matches!(
            self,
            Delete
                | Truncate
                | DropTable
                | DropSchema
                | DropDatabase
                | DropIndex
                | DropView
                | DropMaterializedView
                | DropFunction
                | DropProcedure
                | DropTrigger
                | DropPolicy
                | DropExtension
                | DropType
                | DropSequence
                | DropRole
                | DropOther
        )
    }

    /// Statements that can change data.
    pub fn is_write(&self) -> bool {
        matches!(self.category(), Category::Write)
    }

    /// Statements that change the schema or permissions. These are the ones a
    /// migration should own, not an ad hoc agent session.
    pub fn is_schema_change(&self) -> bool {
        matches!(self.category(), Category::Ddl | Category::Dcl)
    }

    /// Whether the statement takes an ACCESS EXCLUSIVE lock in PostgreSQL,
    /// blocking every concurrent reader and writer of the table.
    pub fn takes_exclusive_lock(&self) -> bool {
        use StatementKind::*;
        matches!(
            self,
            Truncate
                | DropTable
                | DropSchema
                | DropDatabase
                | AlterTable
                | Cluster
                | Reindex
                | DropView
                | DropMaterializedView
        )
    }
}

impl fmt::Display for StatementKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip() {
        for kind in StatementKind::all() {
            assert_eq!(StatementKind::from_str(kind.as_str()), Some(*kind));
        }
    }

    #[test]
    fn identifiers_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for kind in StatementKind::all() {
            assert!(seen.insert(kind.as_str()), "duplicate id {}", kind.as_str());
        }
    }
}
