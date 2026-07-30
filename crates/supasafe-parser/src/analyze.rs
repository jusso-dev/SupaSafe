//! Statement analysis over the parsed AST.
//!
//! Everything SupaSafe decides is derived from the tree the PostgreSQL grammar
//! produced, never from matching text against patterns. `DROP TABLE users` and
//! `drop/**/table"users"` are the same node, and neither is easier to smuggle
//! past than the other.

use sqlparser::ast::{
    Action, AlterColumnOperation, AlterTableOperation, CopySource, CopyTarget, CreateFunctionBody,
    CreateTableOptions, Expr, FromTable, FunctionArguments, GrantObjects, Grantee, GranteeName,
    GranteesType, Ident, LimitClause, ObjectName, ObjectType, Privileges, Query, RoleOption,
    SchemaName, Select, SelectItem, SetExpr, Statement, TableFactor, TableObject, TableWithJoins,
    Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::fallback;
use crate::kind::StatementKind;
use crate::lexer;
use crate::normalize;
use crate::objects::{Access, ObjectKind, ObjectRef};
use crate::predicate::PredicateAnalysis;
use crate::statement::{Batch, Flags, StatementAnalysis};

/// Roles that, on Supabase, are reachable by anyone holding a publishable key.
/// Granting to them is equivalent to granting to the internet.
const PUBLIC_ROLES: &[&str] = &["public", "anon", "authenticated"];

/// Analyse a request that may contain several statements.
pub fn analyze(sql: &str) -> Batch {
    let raws = lexer::split_statements(sql);
    let mut statements = Vec::with_capacity(raws.len());

    for (index, raw) in raws.iter().enumerate() {
        statements.push(analyze_one(&raw.text, index));
    }

    let explicit_transaction = statements
        .first()
        .map(|s| matches!(s.kind, StatementKind::Begin))
        .unwrap_or(false);

    Batch {
        statements,
        explicit_transaction,
        sql: sql.to_string(),
    }
}

/// Analyse a single statement.
pub fn analyze_statement(sql: &str) -> StatementAnalysis {
    analyze_one(sql, 0)
}

fn analyze_one(sql: &str, index: usize) -> StatementAnalysis {
    let dialect = PostgreSqlDialect {};
    match Parser::parse_sql(&dialect, sql) {
        Ok(mut parsed) if parsed.len() == 1 => from_ast(parsed.remove(0), sql, index),
        // The grammar re-split the text. Trust our own split and analyse the
        // first node; the remaining text is still covered because the lexer
        // produced one entry per top-level statement.
        Ok(mut parsed) if !parsed.is_empty() => from_ast(parsed.remove(0), sql, index),
        Ok(_) => fallback::classify(sql, index, None),
        Err(e) => fallback::classify(sql, index, Some(e.to_string())),
    }
}

struct Ctx {
    kind: StatementKind,
    objects: Vec<ObjectRef>,
    predicate: PredicateAnalysis,
    limit: Option<u64>,
    flags: Flags,
    notes: Vec<String>,
}

impl Ctx {
    fn new(kind: StatementKind) -> Self {
        Self {
            kind,
            objects: Vec::new(),
            predicate: PredicateAnalysis::absent(),
            limit: None,
            flags: Flags::default(),
            notes: Vec::new(),
        }
    }

    fn add(&mut self, name: &ObjectName, kind: ObjectKind, access: Access) {
        let (schema, ident) = split_name(name);
        if ident.is_empty() {
            return;
        }
        let obj = ObjectRef::new(schema, ident, kind, access);
        if !self.objects.contains(&obj) {
            self.objects.push(obj);
        }
    }

    fn add_ident(&mut self, ident: &Ident, kind: ObjectKind, access: Access) {
        let obj = ObjectRef::new(None, ident.value.clone(), kind, access);
        if !self.objects.contains(&obj) {
            self.objects.push(obj);
        }
    }

    fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }
}

fn split_name(name: &ObjectName) -> (Option<String>, String) {
    let parts: Vec<String> = name
        .0
        .iter()
        .map(|p| match p.as_ident() {
            Some(i) => i.value.clone(),
            None => p.to_string(),
        })
        .collect();
    match parts.len() {
        0 => (None, String::new()),
        1 => (None, parts[0].clone()),
        // database.schema.object: keep the schema, the database is implied by
        // the connection.
        _ => (
            Some(parts[parts.len() - 2].clone()),
            parts[parts.len() - 1].clone(),
        ),
    }
}

fn from_ast(stmt: Statement, sql: &str, index: usize) -> StatementAnalysis {
    let mut ctx = classify(&stmt);

    ctx.flags.multi_table = ctx
        .objects
        .iter()
        .filter(|o| matches!(o.kind, ObjectKind::Table | ObjectKind::View))
        .count()
        > 1;

    StatementAnalysis {
        index,
        kind: ctx.kind,
        sql: sql.to_string(),
        normalized: normalize::normalize(sql),
        objects: ctx.objects,
        predicate: ctx.predicate,
        limit: ctx.limit,
        flags: ctx.flags,
        parsed: true,
        parse_error: None,
        notes: ctx.notes,
    }
}

fn classify(stmt: &Statement) -> Ctx {
    match stmt {
        Statement::Query(q) => query_stmt(q),
        Statement::Insert(insert) => insert_stmt(insert),
        Statement::Update(update) => update_stmt(update),
        Statement::Delete(delete) => delete_stmt(delete),
        Statement::Merge(merge) => merge_stmt(merge),
        Statement::Truncate(t) => truncate_stmt(t),
        Statement::Copy {
            source, to, target, ..
        } => copy_stmt(source, *to, target),

        Statement::Drop {
            object_type,
            if_exists,
            names,
            cascade,
            ..
        } => drop_stmt(object_type, *if_exists, names, *cascade),

        Statement::AlterTable(alter) => alter_table_stmt(alter),
        Statement::AlterSchema(alter) => {
            let mut ctx = Ctx::new(StatementKind::AlterSchema);
            ctx.add(&alter.name, ObjectKind::Schema, Access::Alter);
            for op in &alter.operations {
                match op {
                    sqlparser::ast::AlterSchemaOperation::OwnerTo { .. } => {
                        ctx.flags.changes_owner = true
                    }
                    sqlparser::ast::AlterSchemaOperation::Rename { .. } => ctx.flags.renames = true,
                    _ => {}
                }
            }
            ctx
        }
        Statement::AlterRole { name, operation } => alter_role_stmt(name, operation),
        Statement::AlterIndex { name, .. } => {
            let mut ctx = Ctx::new(StatementKind::AlterIndex);
            ctx.add(name, ObjectKind::Index, Access::Alter);
            ctx
        }
        Statement::AlterView { name, .. } => {
            let mut ctx = Ctx::new(StatementKind::AlterView);
            ctx.add(name, ObjectKind::View, Access::Alter);
            ctx
        }
        Statement::AlterFunction(_) => Ctx::new(StatementKind::AlterFunction),
        Statement::AlterType(_) => Ctx::new(StatementKind::AlterType),
        Statement::AlterPolicy(_) => {
            let mut ctx = Ctx::new(StatementKind::AlterPolicy);
            ctx.note("row level security policy is being modified");
            ctx
        }

        Statement::CreateTable(create) => {
            let mut ctx = Ctx::new(StatementKind::CreateTable);
            ctx.add(&create.name, ObjectKind::Table, Access::Create);
            ctx.flags.or_replace = create.or_replace;
            ctx.flags.if_exists = create.if_not_exists;
            if let Some(q) = &create.query {
                collect_query_reads(&mut ctx, q);
            }
            if !matches!(create.table_options, CreateTableOptions::None) {
                // Options are recorded for the audit trail but do not change
                // the verdict on their own.
            }
            ctx
        }
        Statement::CreateVirtualTable { name, .. } => {
            let mut ctx = Ctx::new(StatementKind::CreateTable);
            ctx.add(name, ObjectKind::Table, Access::Create);
            ctx
        }
        Statement::CreateSchema {
            schema_name,
            if_not_exists,
            ..
        } => {
            let mut ctx = Ctx::new(StatementKind::CreateSchema);
            ctx.flags.if_exists = *if_not_exists;
            let name = match schema_name {
                SchemaName::Simple(n) => Some(n.clone()),
                SchemaName::NamedAuthorization(n, _) => Some(n.clone()),
                SchemaName::UnnamedAuthorization(_) => None,
            };
            if let Some(n) = name {
                let (_, ident) = split_name(&n);
                let obj = ObjectRef::new(
                    Some(ident.clone()),
                    ident,
                    ObjectKind::Schema,
                    Access::Create,
                );
                ctx.objects.push(obj);
            }
            ctx
        }
        Statement::CreateDatabase { db_name, .. } => {
            let mut ctx = Ctx::new(StatementKind::CreateDatabase);
            ctx.add(db_name, ObjectKind::Database, Access::Create);
            ctx
        }
        Statement::CreateIndex(create) => {
            let mut ctx = Ctx::new(StatementKind::CreateIndex);
            ctx.flags.concurrently = create.concurrently;
            ctx.add(&create.table_name, ObjectKind::Table, Access::Alter);
            if let Some(n) = &create.name {
                ctx.add(n, ObjectKind::Index, Access::Create);
            }
            if !create.concurrently {
                ctx.note(
                    "CREATE INDEX without CONCURRENTLY blocks writes to the table for the \
                     duration of the build",
                );
            }
            ctx
        }
        Statement::CreateView(create) => {
            let mut ctx = Ctx::new(if create.materialized {
                StatementKind::CreateMaterializedView
            } else {
                StatementKind::CreateView
            });
            ctx.flags.or_replace = create.or_replace;
            let obj_kind = if create.materialized {
                ObjectKind::MaterializedView
            } else {
                ObjectKind::View
            };
            ctx.add(&create.name, obj_kind, Access::Create);
            collect_query_reads(&mut ctx, &create.query);
            ctx
        }
        Statement::CreateFunction(create) => {
            let mut ctx = Ctx::new(StatementKind::CreateFunction);
            ctx.add(&create.name, ObjectKind::Function, Access::Create);
            ctx.flags.or_replace = create.or_replace;
            ctx.flags.security_definer = matches!(
                create.security,
                Some(sqlparser::ast::FunctionSecurity::Definer)
            );
            if ctx.flags.security_definer {
                ctx.note(
                    "SECURITY DEFINER functions execute with the owner's privileges and bypass \
                     row level security for their caller",
                );
            }
            if let Some(body) = &create.function_body {
                let text = function_body_text(body);
                mark_opaque_body(&mut ctx, text.as_deref());
            }
            ctx
        }
        Statement::CreateProcedure { name, .. } => {
            let mut ctx = Ctx::new(StatementKind::CreateProcedure);
            ctx.add(name, ObjectKind::Procedure, Access::Create);
            ctx.flags.opaque_body = true;
            ctx
        }
        Statement::CreateTrigger(create) => {
            let mut ctx = Ctx::new(StatementKind::CreateTrigger);
            ctx.add(&create.name, ObjectKind::Trigger, Access::Create);
            ctx.add(&create.table_name, ObjectKind::Table, Access::Alter);
            ctx.flags.or_replace = create.or_replace;
            ctx.flags.opaque_body = true;
            ctx
        }
        Statement::CreatePolicy(create) => {
            let mut ctx = Ctx::new(StatementKind::CreatePolicy);
            ctx.add_ident(&create.name, ObjectKind::Policy, Access::Create);
            ctx.add(&create.table_name, ObjectKind::Table, Access::Alter);
            ctx.flags.strengthens_rls = true;
            ctx
        }
        Statement::CreateExtension(create) => {
            let mut ctx = Ctx::new(StatementKind::CreateExtension);
            ctx.add_ident(&create.name, ObjectKind::Extension, Access::Create);
            ctx.flags.cascade = create.cascade;
            ctx.note(
                "extensions run code inside the database server and can only be installed by a \
                 privileged role",
            );
            ctx
        }
        Statement::CreateRole(create) => {
            let mut ctx = Ctx::new(StatementKind::CreateRole);
            for n in &create.names {
                ctx.add(n, ObjectKind::Role, Access::Create);
            }
            if create.superuser == Some(true)
                || create.bypassrls == Some(true)
                || create.replication == Some(true)
                || create.create_role == Some(true)
                || create.create_db == Some(true)
            {
                ctx.flags.grants_elevated_role = true;
                ctx.note("the new role is created with elevated attributes");
            }
            ctx
        }
        Statement::CreateSequence { name, .. } => {
            let mut ctx = Ctx::new(StatementKind::CreateSequence);
            ctx.add(name, ObjectKind::Sequence, Access::Create);
            ctx
        }
        Statement::CreateType { name, .. } => {
            let mut ctx = Ctx::new(StatementKind::CreateType);
            ctx.add(name, ObjectKind::Type, Access::Create);
            ctx
        }
        Statement::CreateDomain(create) => {
            let mut ctx = Ctx::new(StatementKind::CreateDomain);
            ctx.add(&create.name, ObjectKind::Domain, Access::Create);
            ctx
        }

        Statement::DropFunction(drop) => {
            let mut ctx = Ctx::new(StatementKind::DropFunction);
            ctx.flags.if_exists = drop.if_exists;
            ctx.flags.cascade = matches!(
                drop.drop_behavior,
                Some(sqlparser::ast::DropBehavior::Cascade)
            );
            for d in &drop.func_desc {
                ctx.add(&d.name, ObjectKind::Function, Access::Drop);
            }
            ctx
        }
        Statement::DropProcedure {
            if_exists,
            proc_desc,
            ..
        } => {
            let mut ctx = Ctx::new(StatementKind::DropProcedure);
            ctx.flags.if_exists = *if_exists;
            for d in proc_desc {
                ctx.add(&d.name, ObjectKind::Procedure, Access::Drop);
            }
            ctx
        }
        Statement::DropTrigger(drop) => {
            let mut ctx = Ctx::new(StatementKind::DropTrigger);
            ctx.flags.if_exists = drop.if_exists;
            ctx.add(&drop.trigger_name, ObjectKind::Trigger, Access::Drop);
            if let Some(t) = &drop.table_name {
                ctx.add(t, ObjectKind::Table, Access::Alter);
            }
            ctx.note(
                "dropping a trigger silently removes whatever integrity or audit logic it enforced",
            );
            ctx
        }
        Statement::DropPolicy(drop) => {
            let mut ctx = Ctx::new(StatementKind::DropPolicy);
            ctx.flags.if_exists = drop.if_exists;
            ctx.add_ident(&drop.name, ObjectKind::Policy, Access::Drop);
            ctx.add(&drop.table_name, ObjectKind::Table, Access::Alter);
            ctx.flags.weakens_rls = true;
            ctx.note(
                "dropping a row level security policy can expose every row of the table to \
                 unauthenticated callers",
            );
            ctx
        }
        Statement::DropExtension(drop) => {
            let mut ctx = Ctx::new(StatementKind::DropExtension);
            ctx.flags.if_exists = drop.if_exists;
            ctx.flags.cascade = matches!(
                drop.cascade_or_restrict,
                Some(sqlparser::ast::ReferentialAction::Cascade)
            );
            for n in &drop.names {
                ctx.add_ident(n, ObjectKind::Extension, Access::Drop);
            }
            ctx
        }
        Statement::DropDomain(drop) => {
            let mut ctx = Ctx::new(StatementKind::DropOther);
            ctx.add(&drop.name, ObjectKind::Domain, Access::Drop);
            ctx
        }

        Statement::Grant(grant) => grant_stmt(
            StatementKind::Grant,
            &grant.privileges,
            grant.objects.as_ref(),
            &grant.grantees,
        ),
        Statement::Revoke(revoke) => grant_stmt(
            StatementKind::Revoke,
            &revoke.privileges,
            revoke.objects.as_ref(),
            &revoke.grantees,
        ),
        Statement::Deny(_) => Ctx::new(StatementKind::Deny),

        Statement::Vacuum(v) => {
            let mut ctx = Ctx::new(StatementKind::Vacuum);
            if let Some(t) = &v.table_name {
                ctx.add(t, ObjectKind::Table, Access::Maintain);
            }
            if v.full {
                ctx.note(
                    "VACUUM FULL rewrites the table under an ACCESS EXCLUSIVE lock and needs \
                     free disk space equal to the table size",
                );
            }
            ctx
        }
        Statement::Analyze(a) => {
            let mut ctx = Ctx::new(StatementKind::Analyze);
            if let Some(t) = &a.table_name {
                ctx.add(t, ObjectKind::Table, Access::Maintain);
            }
            ctx
        }

        Statement::Call(func) => {
            let mut ctx = Ctx::new(StatementKind::Call);
            ctx.add(&func.name, ObjectKind::Procedure, Access::Execute);
            ctx.flags.opaque_body = true;
            if let FunctionArguments::List(_) = func.args {
                // Arguments are literals or parameters; nothing further to
                // learn statically.
            }
            ctx.note("the body of a called procedure is not visible to static analysis");
            ctx
        }
        Statement::Execute { name, .. } => {
            let mut ctx = Ctx::new(StatementKind::Execute);
            if let Some(n) = name {
                ctx.add(n, ObjectKind::Unknown, Access::Execute);
            }
            ctx.flags.opaque_body = true;
            ctx
        }
        Statement::Prepare { statement, .. } => {
            // A prepared statement is judged by what it will eventually run.
            let mut inner = classify(statement);
            inner.note("statement is being prepared for later execution");
            inner
        }

        Statement::Explain { statement, .. } => {
            let mut ctx = Ctx::new(StatementKind::Explain);
            let inner = classify(statement);
            // EXPLAIN without ANALYZE does not execute, but EXPLAIN ANALYZE
            // does. Carry the inner objects for visibility either way.
            ctx.objects = inner
                .objects
                .into_iter()
                .map(|mut o| {
                    o.access = Access::Read;
                    o
                })
                .collect();
            ctx
        }
        Statement::ExplainTable { table_name, .. } => {
            let mut ctx = Ctx::new(StatementKind::Explain);
            ctx.add(table_name, ObjectKind::Table, Access::Read);
            ctx
        }

        Statement::StartTransaction { .. } => Ctx::new(StatementKind::Begin),
        Statement::Commit { .. } => Ctx::new(StatementKind::Commit),
        Statement::Rollback { .. } => Ctx::new(StatementKind::Rollback),
        Statement::Savepoint { .. } => Ctx::new(StatementKind::Savepoint),
        Statement::ReleaseSavepoint { .. } => Ctx::new(StatementKind::ReleaseSavepoint),

        Statement::Set(_) => Ctx::new(StatementKind::Set),
        Statement::Reset(_) => Ctx::new(StatementKind::Reset),
        Statement::Discard { .. } => Ctx::new(StatementKind::Discard),
        Statement::Deallocate { .. } => Ctx::new(StatementKind::Deallocate),
        Statement::Declare { .. } => Ctx::new(StatementKind::Declare),
        Statement::Fetch { .. } => Ctx::new(StatementKind::Fetch),
        Statement::Close { .. } => Ctx::new(StatementKind::Close),
        Statement::LISTEN { .. } => Ctx::new(StatementKind::Listen),
        Statement::UNLISTEN { .. } => Ctx::new(StatementKind::Unlisten),
        Statement::NOTIFY { .. } => Ctx::new(StatementKind::Notify),
        Statement::Use(_) => Ctx::new(StatementKind::Use),
        Statement::Comment { object_name, .. } => {
            let mut ctx = Ctx::new(StatementKind::Comment);
            ctx.add(object_name, ObjectKind::Unknown, Access::Alter);
            ctx
        }
        Statement::Lock(_) => {
            let mut ctx = Ctx::new(StatementKind::Lock);
            ctx.note("an explicit table lock blocks other sessions until the transaction ends");
            ctx
        }
        Statement::RenameTable(renames) => {
            let mut ctx = Ctx::new(StatementKind::AlterTable);
            ctx.flags.renames = true;
            for r in renames {
                ctx.add(&r.old_name, ObjectKind::Table, Access::Alter);
            }
            ctx
        }
        Statement::ShowTables { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowSchemas { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowFunctions { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowViews { .. }
        | Statement::ShowObjects(_) => Ctx::new(StatementKind::Show),

        _ => Ctx::new(StatementKind::Unknown),
    }
}

// ---------------------------------------------------------------------------
// DML
// ---------------------------------------------------------------------------

fn query_stmt(q: &Query) -> Ctx {
    let mut ctx = Ctx::new(StatementKind::Select);
    collect_query_reads(&mut ctx, q);
    ctx.limit = limit_value(q.limit_clause.as_ref());
    if !q.locks.is_empty() {
        ctx.flags.locking_read = true;
        ctx.note("SELECT ... FOR UPDATE takes row locks that block concurrent writers");
    }
    if let SetExpr::Select(select) = q.body.as_ref() {
        if select.into.is_some() {
            ctx.flags.select_into = true;
            ctx.kind = StatementKind::CreateTable;
            ctx.note("SELECT ... INTO creates a new table as a side effect");
        }
    }
    ctx
}

fn insert_stmt(insert: &sqlparser::ast::Insert) -> Ctx {
    let mut ctx = Ctx::new(StatementKind::Insert);
    match &insert.table {
        TableObject::TableName(name) => ctx.add(name, ObjectKind::Table, Access::Insert),
        TableObject::TableFunction(f) => ctx.add(&f.name, ObjectKind::Function, Access::Insert),
        TableObject::TableQuery(q) => collect_query_reads(&mut ctx, q),
    }
    if let Some(src) = &insert.source {
        collect_query_reads(&mut ctx, src);
    }
    ctx.flags.returning = insert.returning.is_some();
    if insert.on.is_some() {
        // ON CONFLICT DO UPDATE is an update in disguise.
        if let Some(sqlparser::ast::OnInsert::OnConflict(c)) = &insert.on {
            if matches!(c.action, sqlparser::ast::OnConflictAction::DoUpdate(_)) {
                if let Some(o) = ctx.objects.first_mut() {
                    o.access = Access::Update;
                }
                ctx.note("ON CONFLICT DO UPDATE overwrites existing rows");
            }
        }
    }
    ctx
}

fn update_stmt(update: &sqlparser::ast::Update) -> Ctx {
    let mut ctx = Ctx::new(StatementKind::Update);
    collect_table_with_joins(
        &mut ctx,
        std::slice::from_ref(&update.table),
        Access::Update,
    );
    if let Some(from) = &update.from {
        let tables = match from {
            sqlparser::ast::UpdateTableFromKind::BeforeSet(t)
            | sqlparser::ast::UpdateTableFromKind::AfterSet(t) => t,
        };
        collect_table_with_joins(&mut ctx, tables, Access::Read);
    }
    ctx.predicate = match &update.selection {
        Some(e) => {
            collect_expr_subqueries(&mut ctx, e);
            PredicateAnalysis::analyze(e)
        }
        None => PredicateAnalysis::absent(),
    };
    ctx.limit = update.limit.as_ref().and_then(literal_u64);
    ctx.predicate = ctx.predicate.clone().with_limit(ctx.limit);
    ctx.flags.returning = update.returning.is_some();
    ctx
}

fn delete_stmt(delete: &sqlparser::ast::Delete) -> Ctx {
    let mut ctx = Ctx::new(StatementKind::Delete);
    let tables = match &delete.from {
        FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
    };
    collect_table_with_joins(&mut ctx, tables, Access::Delete);
    for name in &delete.tables {
        ctx.add(name, ObjectKind::Table, Access::Delete);
    }
    if let Some(using) = &delete.using {
        collect_table_with_joins(&mut ctx, using, Access::Read);
    }
    ctx.predicate = match &delete.selection {
        Some(e) => {
            collect_expr_subqueries(&mut ctx, e);
            PredicateAnalysis::analyze(e)
        }
        None => PredicateAnalysis::absent(),
    };
    ctx.limit = delete.limit.as_ref().and_then(literal_u64);
    ctx.predicate = ctx.predicate.clone().with_limit(ctx.limit);
    ctx.flags.returning = delete.returning.is_some();
    ctx
}

fn merge_stmt(merge: &sqlparser::ast::Merge) -> Ctx {
    let mut ctx = Ctx::new(StatementKind::Merge);
    collect_table_factor(&mut ctx, &merge.table, Access::Update);
    collect_table_factor(&mut ctx, &merge.source, Access::Read);
    let deletes = merge
        .clauses
        .iter()
        .any(|c| matches!(c.action, sqlparser::ast::MergeAction::Delete { .. }));
    if deletes {
        if let Some(o) = ctx.objects.first_mut() {
            o.access = Access::Delete;
        }
        ctx.note("this MERGE contains a DELETE branch");
    }
    ctx
}

fn truncate_stmt(t: &sqlparser::ast::Truncate) -> Ctx {
    let mut ctx = Ctx::new(StatementKind::Truncate);
    for target in &t.table_names {
        ctx.add(&target.name, ObjectKind::Table, Access::Truncate);
    }
    ctx.flags.cascade = matches!(t.cascade, Some(sqlparser::ast::CascadeOption::Cascade));
    ctx.flags.if_exists = t.if_exists;
    ctx.note(
        "TRUNCATE removes every row without producing per-row WAL, so it cannot be recovered \
         by replaying the log or undone by a trigger",
    );
    if ctx.flags.cascade {
        ctx.note(
            "CASCADE extends the truncation to every table with a foreign key to these tables",
        );
    }
    ctx
}

fn copy_stmt(source: &CopySource, to: bool, target: &CopyTarget) -> Ctx {
    let mut ctx = Ctx::new(if to {
        StatementKind::CopyTo
    } else {
        StatementKind::CopyFrom
    });
    match source {
        CopySource::Table { table_name, .. } => ctx.add(
            table_name,
            ObjectKind::Table,
            if to { Access::Read } else { Access::Insert },
        ),
        CopySource::Query(q) => collect_query_reads(&mut ctx, q),
    }
    match target {
        CopyTarget::Program { .. } => {
            ctx.flags.copy_program = true;
            ctx.note(
                "COPY ... PROGRAM executes a shell command on the database host as the \
                 postgres operating system user",
            );
        }
        CopyTarget::File { .. } => {
            ctx.flags.copy_file = true;
            ctx.note("COPY reads or writes a file on the database server's filesystem");
        }
        CopyTarget::Stdin | CopyTarget::Stdout => {}
    }
    ctx
}

// ---------------------------------------------------------------------------
// DDL
// ---------------------------------------------------------------------------

fn drop_stmt(
    object_type: &ObjectType,
    if_exists: bool,
    names: &[ObjectName],
    cascade: bool,
) -> Ctx {
    let (kind, obj_kind) = match object_type {
        ObjectType::Table => (StatementKind::DropTable, ObjectKind::Table),
        ObjectType::View => (StatementKind::DropView, ObjectKind::View),
        ObjectType::MaterializedView => (
            StatementKind::DropMaterializedView,
            ObjectKind::MaterializedView,
        ),
        ObjectType::Index => (StatementKind::DropIndex, ObjectKind::Index),
        ObjectType::Schema => (StatementKind::DropSchema, ObjectKind::Schema),
        ObjectType::Database => (StatementKind::DropDatabase, ObjectKind::Database),
        ObjectType::Role | ObjectType::User => (StatementKind::DropRole, ObjectKind::Role),
        ObjectType::Sequence => (StatementKind::DropSequence, ObjectKind::Sequence),
        ObjectType::Type => (StatementKind::DropType, ObjectKind::Type),
        _ => (StatementKind::DropOther, ObjectKind::Unknown),
    };
    let mut ctx = Ctx::new(kind);
    ctx.flags.if_exists = if_exists;
    ctx.flags.cascade = cascade;

    for name in names {
        // `DROP SCHEMA auth` names a schema, so the schema slot is the name
        // itself rather than a qualifier.
        if obj_kind == ObjectKind::Schema {
            let (_, ident) = split_name(name);
            let obj = ObjectRef::new(Some(ident.clone()), ident, ObjectKind::Schema, Access::Drop);
            if !ctx.objects.contains(&obj) {
                ctx.objects.push(obj);
            }
        } else {
            ctx.add(name, obj_kind, Access::Drop);
        }
    }

    if cascade {
        ctx.note(
            "CASCADE also drops every dependent object: views, foreign keys, policies and \
             functions that reference the target",
        );
    }
    if kind == StatementKind::DropSchema {
        ctx.note("dropping a schema removes every table, view and function inside it");
    }
    ctx
}

fn alter_table_stmt(alter: &sqlparser::ast::AlterTable) -> Ctx {
    let mut ctx = Ctx::new(StatementKind::AlterTable);
    ctx.add(&alter.name, ObjectKind::Table, Access::Alter);
    ctx.flags.if_exists = alter.if_exists;
    ctx.flags.only = alter.only;

    for op in &alter.operations {
        match op {
            AlterTableOperation::DropColumn {
                column_names,
                drop_behavior,
                ..
            } => {
                ctx.flags.drops_column = true;
                ctx.flags.cascade |=
                    matches!(drop_behavior, Some(sqlparser::ast::DropBehavior::Cascade));
                let cols = column_names
                    .iter()
                    .map(|c| c.value.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                ctx.note(format!(
                    "dropping column(s) {cols} destroys the stored values; PostgreSQL cannot \
                     restore them without a backup"
                ));
            }
            AlterTableOperation::DropConstraint { .. }
            | AlterTableOperation::DropForeignKey { .. }
            | AlterTableOperation::DropPrimaryKey { .. } => {
                ctx.flags.drops_constraint = true;
                ctx.note("dropping a constraint removes an integrity guarantee the application relies on");
            }
            AlterTableOperation::AddColumn { .. } => ctx.flags.adds_column = true,
            AlterTableOperation::AddConstraint { .. } => {}
            AlterTableOperation::AlterColumn { op, .. } => match op {
                AlterColumnOperation::SetDataType { .. } => {
                    ctx.flags.changes_column_type = true;
                    ctx.note(
                        "changing a column type rewrites the whole table under an ACCESS \
                         EXCLUSIVE lock",
                    );
                }
                AlterColumnOperation::SetNotNull => {
                    ctx.flags.sets_not_null = true;
                    ctx.note("SET NOT NULL scans the table and fails if any existing row is null");
                }
                _ => {}
            },
            AlterTableOperation::OwnerTo { .. } => {
                ctx.flags.changes_owner = true;
                ctx.note("changing the owner transfers full control of the object");
            }
            AlterTableOperation::RenameTable { .. }
            | AlterTableOperation::RenameColumn { .. }
            | AlterTableOperation::RenameConstraint { .. } => {
                ctx.flags.renames = true;
                ctx.note("renaming breaks every client that still refers to the old name");
            }
            AlterTableOperation::DisableRowLevelSecurity => {
                ctx.flags.weakens_rls = true;
                ctx.note(
                    "disabling row level security exposes every row of this table to any role \
                     that can read it, including the anon key on Supabase",
                );
            }
            AlterTableOperation::EnableRowLevelSecurity
            | AlterTableOperation::ForceRowLevelSecurity => ctx.flags.strengthens_rls = true,
            AlterTableOperation::NoForceRowLevelSecurity => ctx.flags.weakens_rls = true,
            AlterTableOperation::DisableTrigger { .. } => {
                ctx.flags.disables_trigger = true;
                ctx.note("disabling a trigger turns off whatever it enforced, silently");
            }
            AlterTableOperation::DropPartitions { .. } => {
                ctx.note("dropping partitions removes the rows they contain");
            }
            _ => {}
        }
    }
    ctx
}

fn alter_role_stmt(name: &Ident, operation: &sqlparser::ast::AlterRoleOperation) -> Ctx {
    let mut ctx = Ctx::new(StatementKind::AlterRole);
    ctx.add_ident(name, ObjectKind::Role, Access::Alter);
    if let sqlparser::ast::AlterRoleOperation::WithOptions { options } = operation {
        for opt in options {
            let elevated = matches!(
                opt,
                RoleOption::SuperUser(true)
                    | RoleOption::BypassRLS(true)
                    | RoleOption::Replication(true)
                    | RoleOption::CreateRole(true)
                    | RoleOption::CreateDB(true)
            );
            if elevated {
                ctx.flags.grants_elevated_role = true;
                ctx.note(
                    "granting SUPERUSER, BYPASSRLS, REPLICATION or CREATEROLE removes every \
                     other safety boundary in the database",
                );
            }
            if matches!(opt, RoleOption::Password(_)) {
                ctx.note("this statement sets a role password");
            }
        }
    }
    ctx
}

fn grant_stmt(
    kind: StatementKind,
    privileges: &Privileges,
    objects: Option<&GrantObjects>,
    grantees: &[Grantee],
) -> Ctx {
    let mut ctx = Ctx::new(kind);
    let access = if kind == StatementKind::Grant {
        Access::Grant
    } else {
        Access::Revoke
    };

    match privileges {
        Privileges::All { .. } => {
            ctx.flags.grants_all = true;
        }
        Privileges::Actions(actions) => {
            for a in actions {
                match a {
                    Action::Ownership => {
                        ctx.flags.grants_elevated_role = true;
                        ctx.note("granting OWNERSHIP transfers full control of the object");
                    }
                    Action::Role { role } | Action::DatabaseRole { role } => {
                        let (_, ident) = split_name(role);
                        if is_elevated_role(&ident) {
                            ctx.flags.grants_elevated_role = true;
                            ctx.note(format!(
                                "granting membership in {ident} hands over privileged access"
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(objs) = objects {
        collect_grant_objects(&mut ctx, objs, access);
    }

    for g in grantees {
        let name = match &g.name {
            Some(GranteeName::ObjectName(n)) => {
                let (_, ident) = split_name(n);
                ident
            }
            Some(GranteeName::UserHost { user, .. }) => user.value.clone(),
            None => String::new(),
        };
        if matches!(g.grantee_type, GranteesType::Public)
            || PUBLIC_ROLES.contains(&name.to_ascii_lowercase().as_str())
        {
            ctx.flags.grants_to_public = true;
        }
        if is_elevated_role(&name) {
            ctx.flags.grants_elevated_role = true;
        }
        if !name.is_empty() {
            ctx.objects
                .push(ObjectRef::new(None, name, ObjectKind::Role, access));
        }
    }

    if kind == StatementKind::Grant && ctx.flags.grants_all && ctx.flags.grants_to_public {
        ctx.note(
            "GRANT ALL to a public role gives every caller holding the anon key full access to \
             these objects",
        );
    }
    ctx
}

fn is_elevated_role(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "superuser"
            | "postgres"
            | "rds_superuser"
            | "supabase_admin"
            | "supabase_auth_admin"
            | "supabase_storage_admin"
            | "pg_execute_server_program"
            | "pg_read_server_files"
            | "pg_write_server_files"
            | "pg_signal_backend"
    )
}

fn collect_grant_objects(ctx: &mut Ctx, objs: &GrantObjects, access: Access) {
    let add_all = |ctx: &mut Ctx, names: &Vec<ObjectName>, kind: ObjectKind| {
        for n in names {
            ctx.add(n, kind, access);
        }
    };
    match objs {
        GrantObjects::Tables(n) => add_all(ctx, n, ObjectKind::Table),
        GrantObjects::Views(n) => add_all(ctx, n, ObjectKind::View),
        GrantObjects::Sequences(n) => add_all(ctx, n, ObjectKind::Sequence),
        GrantObjects::Databases(n) => add_all(ctx, n, ObjectKind::Database),
        GrantObjects::Schemas(n) => {
            for name in n {
                let (_, ident) = split_name(name);
                ctx.objects.push(ObjectRef::new(
                    Some(ident.clone()),
                    ident,
                    ObjectKind::Schema,
                    access,
                ));
            }
        }
        GrantObjects::AllTablesInSchema { schemas }
        | GrantObjects::AllViewsInSchema { schemas }
        | GrantObjects::AllSequencesInSchema { schemas }
        | GrantObjects::AllFunctionsInSchema { schemas }
        | GrantObjects::FutureTablesInSchema { schemas }
        | GrantObjects::FutureViewsInSchema { schemas } => {
            for name in schemas {
                let (_, ident) = split_name(name);
                ctx.objects.push(ObjectRef::new(
                    Some(ident.clone()),
                    ident,
                    ObjectKind::Schema,
                    access,
                ));
            }
            ctx.note("this statement applies to every object in the schema, not a named list");
        }
        GrantObjects::Function { name, .. } => ctx.add(name, ObjectKind::Function, access),
        GrantObjects::Procedure { name, .. } => ctx.add(name, ObjectKind::Procedure, access),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Shared traversal
// ---------------------------------------------------------------------------

fn collect_query_reads(ctx: &mut Ctx, q: &Query) {
    if let Some(with) = &q.with {
        for cte in &with.cte_tables {
            collect_query_reads(ctx, &cte.query);
        }
    }
    collect_set_expr(ctx, &q.body);
}

fn collect_set_expr(ctx: &mut Ctx, body: &SetExpr) {
    match body {
        SetExpr::Select(select) => collect_select(ctx, select),
        SetExpr::Query(q) => collect_query_reads(ctx, q),
        SetExpr::SetOperation { left, right, .. } => {
            collect_set_expr(ctx, left);
            collect_set_expr(ctx, right);
        }
        SetExpr::Insert(stmt) | SetExpr::Update(stmt) | SetExpr::Delete(stmt) => {
            let inner = classify(stmt);
            for o in inner.objects {
                if !ctx.objects.contains(&o) {
                    ctx.objects.push(o);
                }
            }
        }
        SetExpr::Table(t) => {
            if let Some(name) = &t.table_name {
                let obj = ObjectRef::new(
                    t.schema_name.clone(),
                    name.clone(),
                    ObjectKind::Table,
                    Access::Read,
                );
                if !ctx.objects.contains(&obj) {
                    ctx.objects.push(obj);
                }
            }
        }
        SetExpr::Values(_) => {}
        _ => {}
    }
}

fn collect_select(ctx: &mut Ctx, select: &Select) {
    collect_table_with_joins(ctx, &select.from, Access::Read);
    if let Some(sel) = &select.selection {
        collect_expr_subqueries(ctx, sel);
    }
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(e) => collect_expr_subqueries(ctx, e),
            SelectItem::ExprWithAlias { expr, .. } => collect_expr_subqueries(ctx, expr),
            _ => {}
        }
    }
}

fn collect_table_with_joins(ctx: &mut Ctx, tables: &[TableWithJoins], access: Access) {
    for t in tables {
        collect_table_factor(ctx, &t.relation, access);
        for join in &t.joins {
            // Joined tables are read even when the outer statement writes.
            collect_table_factor(ctx, &join.relation, Access::Read);
        }
    }
}

fn collect_table_factor(ctx: &mut Ctx, factor: &TableFactor, access: Access) {
    match factor {
        TableFactor::Table { name, .. } => ctx.add(name, ObjectKind::Table, access),
        TableFactor::Derived { subquery, .. } => collect_query_reads(ctx, subquery),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => collect_table_with_joins(ctx, std::slice::from_ref(table_with_joins), access),
        TableFactor::Function { name, .. } => ctx.add(name, ObjectKind::Function, Access::Execute),
        TableFactor::Pivot { table, .. }
        | TableFactor::Unpivot { table, .. }
        | TableFactor::MatchRecognize { table, .. } => collect_table_factor(ctx, table, access),
        _ => {}
    }
}

/// Pull table references out of subqueries embedded in expressions, so that
/// `DELETE FROM a WHERE id IN (SELECT id FROM b)` reports both tables.
fn collect_expr_subqueries(ctx: &mut Ctx, expr: &Expr) {
    match expr {
        Expr::Subquery(q) | Expr::Exists { subquery: q, .. } => collect_query_reads(ctx, q),
        Expr::InSubquery { subquery, expr, .. } => {
            collect_query_reads(ctx, subquery);
            collect_expr_subqueries(ctx, expr);
        }
        Expr::BinaryOp { left, right, .. } => {
            collect_expr_subqueries(ctx, left);
            collect_expr_subqueries(ctx, right);
        }
        Expr::UnaryOp { expr, .. } | Expr::Nested(expr) | Expr::Cast { expr, .. } => {
            collect_expr_subqueries(ctx, expr)
        }
        Expr::InList { expr, list, .. } => {
            collect_expr_subqueries(ctx, expr);
            for e in list {
                collect_expr_subqueries(ctx, e);
            }
        }
        _ => {}
    }
}

fn limit_value(clause: Option<&LimitClause>) -> Option<u64> {
    match clause? {
        LimitClause::LimitOffset { limit, .. } => limit.as_ref().and_then(literal_u64),
        LimitClause::OffsetCommaLimit { limit, .. } => literal_u64(limit),
    }
}

fn literal_u64(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse::<u64>().ok(),
            _ => None,
        },
        Expr::Nested(inner) => literal_u64(inner),
        _ => None,
    }
}

fn function_body_text(body: &CreateFunctionBody) -> Option<String> {
    let expr = match body {
        CreateFunctionBody::AsBeforeOptions { body, .. } => body,
        CreateFunctionBody::AsAfterOptions(e)
        | CreateFunctionBody::Return(e)
        | CreateFunctionBody::AsReturnExpr(e) => e,
        _ => return None,
    };
    match expr {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) => Some(s.clone()),
            Value::DollarQuotedString(d) => Some(d.value.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Record that a statement carries a body SupaSafe cannot analyse statically,
/// and scan that body lexically for destructive intent.
fn mark_opaque_body(ctx: &mut Ctx, body: Option<&str>) {
    ctx.flags.opaque_body = true;
    if let Some(text) = body {
        let found = fallback::destructive_keywords(text);
        if !found.is_empty() {
            ctx.flags.opaque_body_is_destructive = true;
            ctx.note(format!(
                "the function body contains destructive statements ({}) that will run with \
                 whatever privileges the function has",
                found.join(", ")
            ));
        }
    }
}
