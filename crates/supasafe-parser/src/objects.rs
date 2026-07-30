//! Database objects referenced by a statement, and what the statement does to
//! them.

use serde::{Deserialize, Serialize};
use std::fmt;

/// What kind of thing is being touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Table,
    View,
    MaterializedView,
    Schema,
    Database,
    Index,
    Sequence,
    Function,
    Procedure,
    Trigger,
    Policy,
    Extension,
    Type,
    Domain,
    Role,
    Server,
    Publication,
    Subscription,
    Unknown,
}

impl ObjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectKind::Table => "table",
            ObjectKind::View => "view",
            ObjectKind::MaterializedView => "materialized_view",
            ObjectKind::Schema => "schema",
            ObjectKind::Database => "database",
            ObjectKind::Index => "index",
            ObjectKind::Sequence => "sequence",
            ObjectKind::Function => "function",
            ObjectKind::Procedure => "procedure",
            ObjectKind::Trigger => "trigger",
            ObjectKind::Policy => "policy",
            ObjectKind::Extension => "extension",
            ObjectKind::Type => "type",
            ObjectKind::Domain => "domain",
            ObjectKind::Role => "role",
            ObjectKind::Server => "server",
            ObjectKind::Publication => "publication",
            ObjectKind::Subscription => "subscription",
            ObjectKind::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the statement interacts with the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Insert,
    Update,
    Delete,
    Truncate,
    Create,
    Alter,
    Drop,
    Grant,
    Revoke,
    Execute,
    Maintain,
    Lock,
}

impl Access {
    pub fn as_str(&self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Insert => "insert",
            Access::Update => "update",
            Access::Delete => "delete",
            Access::Truncate => "truncate",
            Access::Create => "create",
            Access::Alter => "alter",
            Access::Drop => "drop",
            Access::Grant => "grant",
            Access::Revoke => "revoke",
            Access::Execute => "execute",
            Access::Maintain => "maintain",
            Access::Lock => "lock",
        }
    }

    /// True when the access can change or destroy existing state.
    pub fn is_mutating(&self) -> bool {
        !matches!(self, Access::Read)
    }

    /// True when the access can lose data that cannot be reconstructed from
    /// the statement itself.
    pub fn is_lossy(&self) -> bool {
        matches!(self, Access::Delete | Access::Truncate | Access::Drop)
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A managed-platform surface a schema belongs to. Supabase projects keep
/// critical machinery in ordinary PostgreSQL schemas, so `DROP SCHEMA auth`
/// looks like any other DDL to a parser that does not know better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedSurface {
    /// GoTrue: users, sessions, refresh tokens, identities, MFA factors.
    SupabaseAuth,
    /// Storage buckets and object metadata.
    SupabaseStorage,
    /// Realtime subscriptions and replication bookkeeping.
    SupabaseRealtime,
    /// Encrypted secrets (Vault / pgsodium).
    SupabaseVault,
    /// Migration history. Rewriting it desynchronises every environment.
    SupabaseMigrations,
    /// Edge function bookkeeping.
    SupabaseFunctions,
    /// The pg_graphql surface.
    SupabaseGraphql,
    /// Where Supabase installs extensions.
    SupabaseExtensions,
    /// pg_cron / pg_net.
    SupabaseJobs,
    /// PostgreSQL's own catalogs.
    SystemCatalog,
    /// Ordinary user schema.
    User,
}

impl ManagedSurface {
    pub fn as_str(&self) -> &'static str {
        match self {
            ManagedSurface::SupabaseAuth => "supabase_auth",
            ManagedSurface::SupabaseStorage => "supabase_storage",
            ManagedSurface::SupabaseRealtime => "supabase_realtime",
            ManagedSurface::SupabaseVault => "supabase_vault",
            ManagedSurface::SupabaseMigrations => "supabase_migrations",
            ManagedSurface::SupabaseFunctions => "supabase_functions",
            ManagedSurface::SupabaseGraphql => "supabase_graphql",
            ManagedSurface::SupabaseExtensions => "supabase_extensions",
            ManagedSurface::SupabaseJobs => "supabase_jobs",
            ManagedSurface::SystemCatalog => "system_catalog",
            ManagedSurface::User => "user",
        }
    }

    /// Human sentence explaining why the surface matters, used verbatim in
    /// block messages and approval cards.
    pub fn why_it_matters(&self) -> Option<&'static str> {
        Some(match self {
            ManagedSurface::SupabaseAuth => {
                "the auth schema holds every user account, session and refresh token; \
                 damage here logs out or deletes your entire user base and cannot be \
                 undone from the application side"
            }
            ManagedSurface::SupabaseStorage => {
                "the storage schema indexes every uploaded object; losing the metadata \
                 orphans the files in object storage"
            }
            ManagedSurface::SupabaseRealtime => {
                "the realtime schema drives replication and subscriptions; changes here \
                 break live clients"
            }
            ManagedSurface::SupabaseVault => {
                "the vault schema stores encrypted secrets; dropped keys are unrecoverable"
            }
            ManagedSurface::SupabaseMigrations => {
                "the migration history table is how every environment agrees on schema \
                 state; rewriting it silently desynchronises staging and production"
            }
            ManagedSurface::SupabaseFunctions => "this schema tracks deployed edge functions",
            ManagedSurface::SupabaseGraphql => {
                "the GraphQL schema is regenerated by pg_graphql; manual changes are lost \
                 or break the API"
            }
            ManagedSurface::SupabaseExtensions => {
                "Supabase installs extensions into this schema; dropping it disables \
                 features across the project"
            }
            ManagedSurface::SupabaseJobs => {
                "scheduled jobs and outbound HTTP live here; changes stop background work"
            }
            ManagedSurface::SystemCatalog => {
                "these are PostgreSQL's own catalogs; direct modification corrupts the \
                 database"
            }
            ManagedSurface::User => return None,
        })
    }

    /// Surfaces whose destruction is never a legitimate agent action.
    pub fn is_protected(&self) -> bool {
        !matches!(self, ManagedSurface::User)
    }

    /// Classify a schema name.
    pub fn classify_schema(schema: &str) -> ManagedSurface {
        let s = schema.to_ascii_lowercase();
        match s.as_str() {
            "auth" => ManagedSurface::SupabaseAuth,
            "storage" => ManagedSurface::SupabaseStorage,
            "realtime" | "_realtime" => ManagedSurface::SupabaseRealtime,
            "vault" | "pgsodium" | "pgsodium_masks" => ManagedSurface::SupabaseVault,
            "supabase_migrations" => ManagedSurface::SupabaseMigrations,
            "supabase_functions" => ManagedSurface::SupabaseFunctions,
            "graphql" | "graphql_public" => ManagedSurface::SupabaseGraphql,
            "extensions" => ManagedSurface::SupabaseExtensions,
            "cron" | "net" => ManagedSurface::SupabaseJobs,
            "pg_catalog" | "information_schema" | "pg_toast" | "pg_temp" => {
                ManagedSurface::SystemCatalog
            }
            _ => {
                if s.starts_with("pg_") {
                    ManagedSurface::SystemCatalog
                } else {
                    ManagedSurface::User
                }
            }
        }
    }
}

impl fmt::Display for ManagedSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single object reference extracted from the AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Schema, when the statement qualified the name. `None` means the name
    /// resolves through `search_path` at execution time.
    pub schema: Option<String>,
    pub name: String,
    pub kind: ObjectKind,
    pub access: Access,
    pub surface: ManagedSurface,
}

impl ObjectRef {
    pub fn new(
        schema: Option<String>,
        name: impl Into<String>,
        kind: ObjectKind,
        access: Access,
    ) -> Self {
        let surface = match schema.as_deref() {
            Some(s) => ManagedSurface::classify_schema(s),
            // An unqualified name resolves through search_path, which in
            // Supabase starts at `public`. Treat it as a user object but let
            // callers re-resolve against a live catalog when one is available.
            None => ManagedSurface::User,
        };
        Self {
            schema,
            name: name.into(),
            kind,
            access,
            surface,
        }
    }

    /// A schema-qualified name for display and glob matching. Unqualified
    /// names are reported against the assumed default schema.
    pub fn qualified(&self) -> String {
        match &self.schema {
            Some(s) => format!("{s}.{}", self.name),
            None => format!("public.{}", self.name),
        }
    }

    /// The name exactly as the statement wrote it.
    pub fn as_written(&self) -> String {
        match &self.schema {
            Some(s) => format!("{s}.{}", self.name),
            None => self.name.clone(),
        }
    }

    /// True when this reference lands on a protected managed surface.
    pub fn is_protected(&self) -> bool {
        self.surface.is_protected()
    }

    /// Re-resolve an unqualified reference against a default schema, usually
    /// the head of the connection's `search_path`.
    pub fn resolve_with_default_schema(&mut self, default_schema: &str) {
        if self.schema.is_none() {
            self.schema = Some(default_schema.to_string());
            self.surface = ManagedSurface::classify_schema(default_schema);
        }
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.kind, self.as_written())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_supabase_schemas() {
        assert_eq!(
            ManagedSurface::classify_schema("auth"),
            ManagedSurface::SupabaseAuth
        );
        assert_eq!(
            ManagedSurface::classify_schema("AUTH"),
            ManagedSurface::SupabaseAuth
        );
        assert_eq!(
            ManagedSurface::classify_schema("storage"),
            ManagedSurface::SupabaseStorage
        );
        assert_eq!(
            ManagedSurface::classify_schema("pg_catalog"),
            ManagedSurface::SystemCatalog
        );
        assert_eq!(
            ManagedSurface::classify_schema("public"),
            ManagedSurface::User
        );
    }

    #[test]
    fn qualified_defaults_to_public() {
        let r = ObjectRef::new(None, "users", ObjectKind::Table, Access::Read);
        assert_eq!(r.qualified(), "public.users");
        assert_eq!(r.as_written(), "users");
    }
}
