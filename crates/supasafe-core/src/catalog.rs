//! A snapshot of what the database actually contains.
//!
//! Static analysis can tell you `DELETE FROM orders` has no WHERE clause. It
//! cannot tell you that `orders` holds forty million rows, that `order_items`
//! has a foreign key to it with `ON DELETE CASCADE`, and that the delete will
//! therefore take two tables with it. That needs the catalogue.
//!
//! SupaSafe fills this in from its own read-only introspection connection when
//! one is configured, and degrades to static analysis when it is not. Every
//! consumer has to cope with `None`, because the common case at first run is a
//! proxy that has credentials for nothing but forwarding.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// What PostgreSQL does to child rows when a parent row goes away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDelete {
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

impl OnDelete {
    pub fn from_pg_char(c: char) -> OnDelete {
        match c {
            'c' => OnDelete::Cascade,
            'n' => OnDelete::SetNull,
            'd' => OnDelete::SetDefault,
            'r' => OnDelete::Restrict,
            _ => OnDelete::NoAction,
        }
    }

    /// True when deleting the parent silently changes the child.
    pub fn touches_children(&self) -> bool {
        matches!(
            self,
            OnDelete::Cascade | OnDelete::SetNull | OnDelete::SetDefault
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            OnDelete::NoAction => "NO ACTION",
            OnDelete::Restrict => "RESTRICT",
            OnDelete::Cascade => "CASCADE",
            OnDelete::SetNull => "SET NULL",
            OnDelete::SetDefault => "SET DEFAULT",
        }
    }
}

/// Statistics for one table, as PostgreSQL reports them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TableStats {
    pub schema: String,
    pub name: String,
    /// `pg_class.reltuples`, the planner's own estimate. Approximate by
    /// definition, and worth stating as such wherever it is shown.
    pub estimated_rows: u64,
    /// Total size including indexes and TOAST, in bytes.
    pub total_bytes: u64,
    pub index_count: u32,
    /// Row level security is enabled on the table.
    pub rls_enabled: bool,
    /// Number of RLS policies attached.
    pub policy_count: u32,
    /// Triggers that would fire on a write.
    pub trigger_count: u32,
    /// The table is published for logical replication.
    pub replicated: bool,
}

impl TableStats {
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.schema, self.name)
    }
}

/// A foreign key from `child` to `parent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKey {
    pub name: String,
    pub child: String,
    pub parent: String,
    pub on_delete: OnDelete,
}

/// One hop in a cascade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CascadeStep {
    pub table: String,
    pub via_constraint: String,
    pub on_delete: OnDelete,
    /// How many foreign key hops from the statement's target.
    pub depth: usize,
}

/// A point-in-time view of the objects a statement might touch.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    /// Keyed by `schema.table`.
    pub tables: HashMap<String, TableStats>,
    pub foreign_keys: Vec<ForeignKey>,
    /// Primary key columns per table, so key-lookup detection can stop
    /// guessing from column names.
    pub primary_keys: HashMap<String, Vec<String>>,
    /// When the snapshot was taken, as a Unix timestamp.
    pub captured_at: i64,
}

impl CatalogSnapshot {
    pub fn table(&self, qualified: &str) -> Option<&TableStats> {
        self.tables.get(&qualified.to_ascii_lowercase())
    }

    pub fn insert_table(&mut self, stats: TableStats) {
        self.tables
            .insert(stats.qualified().to_ascii_lowercase(), stats);
    }

    /// Foreign keys pointing *at* this table, i.e. the tables that would be
    /// affected if its rows went away.
    pub fn dependents(&self, qualified: &str) -> Vec<&ForeignKey> {
        let target = qualified.to_ascii_lowercase();
        self.foreign_keys
            .iter()
            .filter(|fk| fk.parent.to_ascii_lowercase() == target)
            .collect()
    }

    /// Walk the foreign key graph to find every table a delete would reach.
    ///
    /// Stops at `RESTRICT`/`NO ACTION` edges, because those raise an error
    /// rather than propagating, and guards against cycles.
    pub fn cascade_from(&self, qualified: &str) -> Vec<CascadeStep> {
        let mut out: Vec<CascadeStep> = Vec::new();
        let mut seen: Vec<String> = vec![qualified.to_ascii_lowercase()];
        let mut frontier = vec![(qualified.to_ascii_lowercase(), 0usize)];

        while let Some((table, depth)) = frontier.pop() {
            // A pathological schema should not turn analysis into a hang.
            if depth >= 10 {
                continue;
            }
            for fk in self.dependents(&table) {
                if !fk.on_delete.touches_children() {
                    continue;
                }
                let child = fk.child.to_ascii_lowercase();
                if seen.contains(&child) {
                    continue;
                }
                seen.push(child.clone());
                out.push(CascadeStep {
                    table: fk.child.clone(),
                    via_constraint: fk.name.clone(),
                    on_delete: fk.on_delete,
                    depth: depth + 1,
                });
                if fk.on_delete == OnDelete::Cascade {
                    frontier.push((child, depth + 1));
                }
            }
        }
        out.sort_by_key(|s| (s.depth, s.table.clone()));
        out
    }

    /// Rows in a table, when known.
    pub fn rows(&self, qualified: &str) -> Option<u64> {
        self.table(qualified).map(|t| t.estimated_rows)
    }

    /// Total rows across every table a cascade would reach.
    pub fn cascade_rows(&self, qualified: &str) -> u64 {
        self.cascade_from(qualified)
            .iter()
            .filter(|s| s.on_delete == OnDelete::Cascade)
            .filter_map(|s| self.rows(&s.table))
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty() && self.foreign_keys.is_empty()
    }
}

/// The queries SupaSafe runs to build a snapshot.
///
/// They live here rather than in the proxy so that the shape of the data and
/// the SQL that produces it stay next to each other. Every one of them is a
/// read against a system catalogue.
pub mod queries {
    /// Table statistics, sizes and security posture.
    pub const TABLES: &str = "\
SELECT n.nspname                                    AS schema,
       c.relname                                    AS name,
       GREATEST(c.reltuples, 0)::bigint             AS estimated_rows,
       pg_total_relation_size(c.oid)                AS total_bytes,
       (SELECT count(*) FROM pg_index i WHERE i.indrelid = c.oid)::int    AS index_count,
       c.relrowsecurity                             AS rls_enabled,
       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)::int   AS policy_count,
       (SELECT count(*) FROM pg_trigger t
         WHERE t.tgrelid = c.oid AND NOT t.tgisinternal)::int             AS trigger_count
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'p')
   AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')";

    /// Foreign keys and their delete behaviour.
    pub const FOREIGN_KEYS: &str = "\
SELECT con.conname                                        AS name,
       cn.nspname || '.' || child.relname                 AS child,
       pn.nspname || '.' || parent.relname                AS parent,
       con.confdeltype                                    AS on_delete
  FROM pg_constraint con
  JOIN pg_class child   ON child.oid  = con.conrelid
  JOIN pg_namespace cn  ON cn.oid     = child.relnamespace
  JOIN pg_class parent  ON parent.oid = con.confrelid
  JOIN pg_namespace pn  ON pn.oid     = parent.relnamespace
 WHERE con.contype = 'f'";

    /// Primary key columns, so key-lookup detection can use the real key.
    pub const PRIMARY_KEYS: &str = "\
SELECT n.nspname || '.' || c.relname AS table_name,
       a.attname                     AS column_name
  FROM pg_index i
  JOIN pg_class c      ON c.oid = i.indrelid
  JOIN pg_namespace n  ON n.oid = c.relnamespace
  JOIN pg_attribute a  ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
 WHERE i.indisprimary";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(name: &str, rows: u64) -> TableStats {
        let (schema, table) = name.split_once('.').unwrap();
        TableStats {
            schema: schema.into(),
            name: table.into(),
            estimated_rows: rows,
            total_bytes: rows * 100,
            index_count: 1,
            rls_enabled: false,
            policy_count: 0,
            trigger_count: 0,
            replicated: false,
        }
    }

    fn fk(name: &str, child: &str, parent: &str, on_delete: OnDelete) -> ForeignKey {
        ForeignKey {
            name: name.into(),
            child: child.into(),
            parent: parent.into(),
            on_delete,
        }
    }

    fn snapshot() -> CatalogSnapshot {
        let mut c = CatalogSnapshot::default();
        c.insert_table(table("public.users", 1_000));
        c.insert_table(table("public.orders", 50_000));
        c.insert_table(table("public.order_items", 400_000));
        c.insert_table(table("public.invoices", 12));
        c.foreign_keys = vec![
            fk(
                "orders_user_fk",
                "public.orders",
                "public.users",
                OnDelete::Cascade,
            ),
            fk(
                "items_order_fk",
                "public.order_items",
                "public.orders",
                OnDelete::Cascade,
            ),
            fk(
                "invoices_user_fk",
                "public.invoices",
                "public.users",
                OnDelete::Restrict,
            ),
        ];
        c
    }

    #[test]
    fn finds_direct_dependents() {
        let c = snapshot();
        let deps = c.dependents("public.users");
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn cascade_follows_the_chain() {
        let c = snapshot();
        let steps = c.cascade_from("public.users");
        let tables: Vec<_> = steps.iter().map(|s| s.table.as_str()).collect();
        assert!(tables.contains(&"public.orders"));
        // Two hops away, through orders.
        assert!(tables.contains(&"public.order_items"));
        // RESTRICT does not propagate.
        assert!(!tables.contains(&"public.invoices"));
    }

    #[test]
    fn cascade_rows_add_up() {
        let c = snapshot();
        assert_eq!(c.cascade_rows("public.users"), 50_000 + 400_000);
    }

    #[test]
    fn cycles_do_not_hang() {
        let mut c = CatalogSnapshot::default();
        c.insert_table(table("public.a", 1));
        c.insert_table(table("public.b", 1));
        c.foreign_keys = vec![
            fk("ab", "public.a", "public.b", OnDelete::Cascade),
            fk("ba", "public.b", "public.a", OnDelete::Cascade),
        ];
        assert_eq!(c.cascade_from("public.a").len(), 1);
    }

    #[test]
    fn lookups_are_case_insensitive() {
        let c = snapshot();
        assert!(c.table("PUBLIC.USERS").is_some());
    }

    #[test]
    fn on_delete_maps_from_pg_chars() {
        assert_eq!(OnDelete::from_pg_char('c'), OnDelete::Cascade);
        assert_eq!(OnDelete::from_pg_char('a'), OnDelete::NoAction);
        assert!(!OnDelete::Restrict.touches_children());
    }
}
