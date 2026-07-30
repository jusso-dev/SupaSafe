//! Rollback planning.
//!
//! Before a statement runs, SupaSafe works out how you would get back. Some
//! changes reverse cleanly and SupaSafe can write the reverse migration for
//! you. Some do not reverse at all, and the honest answer is "restore from a
//! backup, and here is which one".
//!
//! Saying "irreversible" plainly is the point. An approval card that implies
//! everything can be undone teaches people to approve without reading.

use serde::{Deserialize, Serialize};
use supasafe_parser::{StatementAnalysis, StatementKind};

/// How recoverable a change is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// Nothing to undo: the statement changes no state.
    NoChange,
    /// SupaSafe can generate SQL that puts things back exactly.
    Automatic,
    /// Reversible, but only with information the statement does not carry,
    /// such as the rows it deleted.
    NeedsSnapshot,
    /// Cannot be reversed from inside the database at all.
    Irreversible,
}

impl Reversibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reversibility::NoChange => "no_change",
            Reversibility::Automatic => "automatic",
            Reversibility::NeedsSnapshot => "needs_snapshot",
            Reversibility::Irreversible => "irreversible",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Reversibility::NoChange => {
                "this statement changes nothing, so there is nothing to undo"
            }
            Reversibility::Automatic => "this can be reversed with a statement SupaSafe can write",
            Reversibility::NeedsSnapshot => {
                "this can only be reversed from a copy of the data taken beforehand"
            }
            Reversibility::Irreversible => {
                "this cannot be reversed from inside the database; recovery means restoring a \
                 backup, and everything written since that backup is lost"
            }
        }
    }
}

/// What to do if the change turns out to be wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub reversibility: Reversibility,
    /// SQL that reverses the change, when one statement can.
    pub reverse_sql: Option<String>,
    /// Steps a human should follow.
    pub steps: Vec<String>,
    /// What is lost even if every step is followed.
    pub caveats: Vec<String>,
}

impl RollbackPlan {
    pub fn none() -> RollbackPlan {
        RollbackPlan {
            reversibility: Reversibility::NoChange,
            reverse_sql: None,
            steps: Vec::new(),
            caveats: Vec::new(),
        }
    }

    /// A single sentence for a notification.
    pub fn summary(&self) -> String {
        match self.reversibility {
            Reversibility::Automatic => match &self.reverse_sql {
                Some(sql) => format!("reversible with: {sql}"),
                None => "reversible".to_string(),
            },
            other => other.describe().to_string(),
        }
    }
}

/// Work out how to get back from a statement.
pub fn plan(stmt: &StatementAnalysis, recovery_point: Option<&str>) -> RollbackPlan {
    use StatementKind::*;

    let target = stmt
        .primary_object()
        .map(|o| o.as_written())
        .unwrap_or_else(|| "the affected object".to_string());

    let mut steps = Vec::new();
    let mut caveats = Vec::new();
    let mut reverse_sql = None;

    let reversibility = match stmt.kind {
        // --- nothing to undo ---
        Select | Explain | Show | Fetch | CopyTo | Begin | Commit | Rollback | Savepoint
        | ReleaseSavepoint | Set | Reset | Discard | Listen | Unlisten | Notify => {
            Reversibility::NoChange
        }

        // --- reverses cleanly ---
        CreateTable => {
            reverse_sql = Some(format!("DROP TABLE {target};"));
            steps.push(format!(
                "Drop the table that was created: DROP TABLE {target};"
            ));
            Reversibility::Automatic
        }
        CreateIndex => {
            reverse_sql = Some(format!("DROP INDEX CONCURRENTLY {target};"));
            steps.push(
                "Drop the index. Use CONCURRENTLY so the drop does not block reads.".to_string(),
            );
            Reversibility::Automatic
        }
        CreateView | CreateMaterializedView => {
            reverse_sql = Some(format!("DROP VIEW {target};"));
            Reversibility::Automatic
        }
        CreateSchema => {
            reverse_sql = Some(format!("DROP SCHEMA {target};"));
            Reversibility::Automatic
        }
        CreateExtension => {
            reverse_sql = Some(format!("DROP EXTENSION {target};"));
            caveats.push(
                "Dropping an extension also drops every object that depends on it.".to_string(),
            );
            Reversibility::Automatic
        }
        CreatePolicy => {
            reverse_sql = Some(format!("DROP POLICY ... ON {target};"));
            Reversibility::Automatic
        }

        AlterTable if stmt.flags.adds_column && !stmt.flags.drops_column => {
            steps.push(
                "Drop the column that was added. The data written into it since is lost, which \
                 is usually fine for a column that did not exist an hour ago."
                    .to_string(),
            );
            reverse_sql = Some(format!("ALTER TABLE {target} DROP COLUMN <column>;"));
            Reversibility::Automatic
        }
        AlterTable if stmt.flags.weakens_rls => {
            reverse_sql = Some(format!("ALTER TABLE {target} ENABLE ROW LEVEL SECURITY;"));
            steps.push("Re-enable row level security on the table.".to_string());
            caveats.push(
                "Re-enabling the policy does not undo any read that happened while it was off. \
                 Treat the window as a potential data exposure."
                    .to_string(),
            );
            Reversibility::Automatic
        }
        AlterTable if stmt.flags.changes_owner => {
            reverse_sql = Some(format!("ALTER TABLE {target} OWNER TO <previous owner>;"));
            steps.push("Set the owner back. You need to know who it was before.".to_string());
            Reversibility::Automatic
        }
        AlterTable if stmt.flags.renames => {
            reverse_sql = Some(format!("ALTER TABLE {target} RENAME TO <previous name>;"));
            Reversibility::Automatic
        }

        Grant => {
            reverse_sql = Some("REVOKE <the same privileges> FROM <the same grantee>;".to_string());
            caveats.push(
                "Revoking later does not undo anything that was read or written while the grant \
                 was in place."
                    .to_string(),
            );
            Reversibility::Automatic
        }
        Revoke => {
            reverse_sql = Some("GRANT <the same privileges> TO <the same grantee>;".to_string());
            Reversibility::Automatic
        }

        Insert => {
            steps.push(
                "Delete the rows that were inserted. Use the RETURNING output or the primary \
                 keys from the audit record to identify them."
                    .to_string(),
            );
            Reversibility::NeedsSnapshot
        }

        // --- needs the old data ---
        Update => {
            steps.push(format!(
                "Restore the previous values in {target} from the snapshot taken before this \
                 statement."
            ));
            caveats.push(
                "An UPDATE overwrites in place. Without a snapshot, the previous values are \
                 gone."
                    .to_string(),
            );
            Reversibility::NeedsSnapshot
        }
        Delete | Merge => {
            steps.push(format!(
                "Re-insert the deleted rows into {target} from the snapshot taken before this \
                 statement."
            ));
            caveats.push(
                "Foreign keys mean the rows have to go back in dependency order, parents first."
                    .to_string(),
            );
            Reversibility::NeedsSnapshot
        }

        AlterTable if stmt.flags.drops_column => {
            steps.push(format!(
                "Add the column back to {target}, then restore its values from the snapshot."
            ));
            caveats.push(
                "Adding the column back gives you a column full of nulls. The values only come \
                 back from a copy taken beforehand."
                    .to_string(),
            );
            Reversibility::NeedsSnapshot
        }

        // --- gone ---
        Truncate => {
            steps.push(format!(
                "Restore {target} from the snapshot taken before this statement, or from a \
                 backup."
            ));
            caveats.push(
                "TRUNCATE writes no per-row WAL, so point-in-time recovery cannot replay back to \
                 just before it. You need a copy of the rows."
                    .to_string(),
            );
            Reversibility::Irreversible
        }
        DropTable | DropSchema | DropDatabase | DropMaterializedView => {
            steps.push(format!(
                "Restore {target} from the snapshot taken before this statement, or from the \
                 most recent backup."
            ));
            steps.push(
                "On Supabase, use point-in-time recovery from the dashboard to restore the \
                 project to a moment before this statement ran."
                    .to_string(),
            );
            caveats.push(
                "Restoring the whole database also rolls back everything else written since the \
                 restore point."
                    .to_string(),
            );
            Reversibility::Irreversible
        }
        DropRole => {
            steps.push(
                "Recreate the role and re-grant its privileges. The grants are not recorded \
                 anywhere except your migrations."
                    .to_string(),
            );
            Reversibility::Irreversible
        }

        // --- unknown territory ---
        DoBlock | Call | Execute => {
            steps.push(
                "SupaSafe cannot see what this executed, so it cannot tell you how to undo it. \
                 Check the audit trail for what actually changed."
                    .to_string(),
            );
            Reversibility::NeedsSnapshot
        }

        _ => {
            if stmt.kind.is_destructive() {
                Reversibility::Irreversible
            } else if stmt.kind.is_schema_change() {
                steps.push(
                    "Reverse the schema change with the corresponding migration.".to_string(),
                );
                Reversibility::Automatic
            } else {
                Reversibility::NeedsSnapshot
            }
        }
    };

    match recovery_point {
        Some(point) if reversibility != Reversibility::NoChange => {
            steps.insert(
                0,
                format!("Recovery point taken before this statement: {point}"),
            );
        }
        None if matches!(
            reversibility,
            Reversibility::NeedsSnapshot | Reversibility::Irreversible
        ) =>
        {
            caveats.push(
                "No snapshot was taken before this statement, so there is nothing to restore \
                 from except your own backups."
                    .to_string(),
            );
        }
        _ => {}
    }

    if stmt.flags.cascade {
        caveats.push(
            "CASCADE removed dependent objects that the statement never named. Restoring the \
             named object does not bring them back."
                .to_string(),
        );
    }

    RollbackPlan {
        reversibility,
        reverse_sql,
        steps,
        caveats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supasafe_parser::analyze_statement;

    fn p(sql: &str) -> RollbackPlan {
        plan(&analyze_statement(sql), None)
    }

    #[test]
    fn reads_have_nothing_to_undo() {
        assert_eq!(p("SELECT 1").reversibility, Reversibility::NoChange);
    }

    #[test]
    fn create_table_reverses_automatically() {
        let plan = p("CREATE TABLE public.widgets (id int)");
        assert_eq!(plan.reversibility, Reversibility::Automatic);
        assert!(plan.reverse_sql.unwrap().starts_with("DROP TABLE"));
    }

    #[test]
    fn drop_table_is_irreversible_and_says_so() {
        let plan = p("DROP TABLE public.users");
        assert_eq!(plan.reversibility, Reversibility::Irreversible);
        assert!(plan.steps.iter().any(|s| s.contains("point-in-time")));
        assert!(plan
            .caveats
            .iter()
            .any(|c| c.contains("nothing to restore from") || c.contains("rolls back")));
    }

    #[test]
    fn truncate_explains_why_pitr_does_not_help() {
        let plan = p("TRUNCATE TABLE events");
        assert_eq!(plan.reversibility, Reversibility::Irreversible);
        assert!(plan.caveats.iter().any(|c| c.contains("no per-row WAL")));
    }

    #[test]
    fn update_needs_the_old_values() {
        let plan = p("UPDATE users SET email = 'x' WHERE id = 1");
        assert_eq!(plan.reversibility, Reversibility::NeedsSnapshot);
    }

    #[test]
    fn dropping_a_column_needs_a_snapshot_not_just_a_re_add() {
        let plan = p("ALTER TABLE users DROP COLUMN email");
        assert_eq!(plan.reversibility, Reversibility::NeedsSnapshot);
        assert!(plan.caveats.iter().any(|c| c.contains("full of nulls")));
    }

    #[test]
    fn disabling_rls_can_be_re_enabled_but_the_exposure_stands() {
        let plan = p("ALTER TABLE t DISABLE ROW LEVEL SECURITY");
        assert_eq!(plan.reversibility, Reversibility::Automatic);
        assert!(plan.caveats.iter().any(|c| c.contains("exposure")));
    }

    #[test]
    fn a_recovery_point_is_named_first() {
        let plan = plan(&analyze_statement("DROP TABLE users"), Some("snap-123"));
        assert!(plan.steps[0].contains("snap-123"));
    }

    #[test]
    fn cascade_is_called_out() {
        let plan = p("DROP TABLE users CASCADE");
        assert!(plan.caveats.iter().any(|c| c.contains("CASCADE")));
    }
}
