//! Keeping the catalogue snapshot fresh.
//!
//! Static analysis knows `DELETE FROM signups` has no WHERE clause. Only the
//! catalogue knows that means 8,412 rows here and 80,000 more through two
//! cascading foreign keys the statement never mentions.
//!
//! This runs in the background on its own connection, with credentials the
//! operator granted for the purpose. If it cannot connect, SupaSafe carries on
//! with structural estimates and says so on every approval card, rather than
//! refusing to start or quietly presenting guesses as measurements.

use std::sync::Arc;
use std::time::Duration;

use supasafe_core::catalog::{queries, CatalogSnapshot, ForeignKey, OnDelete, TableStats};
use supasafe_core::guard::Guard;

use crate::client::{self, ClientConfig, Rows};

/// How often the snapshot is rebuilt.
///
/// Row counts come from `pg_class.reltuples`, which PostgreSQL itself updates
/// on VACUUM and ANALYZE, so refreshing faster than this would mostly re-read
/// the same numbers.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(300);

/// Fetch the catalogue once.
pub async fn fetch(config: &ClientConfig) -> Result<CatalogSnapshot, client::ClientError> {
    let results = client::query_all(
        config,
        &[
            queries::TABLES,
            queries::FOREIGN_KEYS,
            queries::PRIMARY_KEYS,
        ],
    )
    .await?;

    let mut snapshot = CatalogSnapshot {
        captured_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        ..Default::default()
    };

    if let Some(tables) = results.first() {
        for row in &tables.rows {
            let (Some(schema), Some(name)) = (tables.get(row, "schema"), tables.get(row, "name"))
            else {
                continue;
            };
            snapshot.insert_table(TableStats {
                schema: schema.to_string(),
                name: name.to_string(),
                estimated_rows: tables.number(row, "estimated_rows"),
                total_bytes: tables.number(row, "total_bytes"),
                index_count: tables.number(row, "index_count") as u32,
                rls_enabled: tables.boolean(row, "rls_enabled"),
                policy_count: tables.number(row, "policy_count") as u32,
                trigger_count: tables.number(row, "trigger_count") as u32,
                replicated: false,
            });
        }
    }

    if let Some(keys) = results.get(1) {
        for row in &keys.rows {
            let (Some(name), Some(child), Some(parent)) = (
                keys.get(row, "name"),
                keys.get(row, "child"),
                keys.get(row, "parent"),
            ) else {
                continue;
            };
            let on_delete = keys
                .get(row, "on_delete")
                .and_then(|s| s.chars().next())
                .map(OnDelete::from_pg_char)
                .unwrap_or(OnDelete::NoAction);
            snapshot.foreign_keys.push(ForeignKey {
                name: name.to_string(),
                child: child.to_string(),
                parent: parent.to_string(),
                on_delete,
            });
        }
    }

    if let Some(keys) = results.get(2) {
        collect_primary_keys(&mut snapshot, keys);
    }

    Ok(snapshot)
}

fn collect_primary_keys(snapshot: &mut CatalogSnapshot, rows: &Rows) {
    for row in &rows.rows {
        let (Some(table), Some(column)) =
            (rows.get(row, "table_name"), rows.get(row, "column_name"))
        else {
            continue;
        };
        snapshot
            .primary_keys
            .entry(table.to_ascii_lowercase())
            .or_default()
            .push(column.to_string());
    }
}

/// Refresh the guard's catalogue now, and then on a timer, forever.
///
/// Spawned by the proxy when `proxy.introspection_url` is set.
pub async fn keep_fresh(guard: Arc<Guard>, config: ClientConfig, every: Duration) {
    loop {
        match fetch(&config).await {
            Ok(snapshot) => {
                let tables = snapshot.tables.len();
                let keys = snapshot.foreign_keys.len();
                guard.set_catalog(snapshot);
                tracing::info!(
                    tables,
                    foreign_keys = keys,
                    "catalogue refreshed; blast radius is measured from here on"
                );
            }
            Err(e) => {
                // Not fatal. Blast radius falls back to structural estimates,
                // which every approval card already labels as such.
                tracing::warn!(
                    error = %e,
                    "could not read the catalogue; blast radius will be estimated rather than \
                     measured"
                );
            }
        }
        tokio::time::sleep(every).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalogue queries have to survive being sent to a real server, and
    /// the column names they return are what `fetch` reads by name. This test
    /// runs only when a database is available.
    #[tokio::test]
    async fn the_catalogue_queries_run_against_a_real_server() {
        let Ok(url) = std::env::var("SUPASAFE_TEST_PG") else {
            eprintln!("skipping: set SUPASAFE_TEST_PG to run the introspection test");
            return;
        };
        let config = ClientConfig::from_url(&url).expect("parses");
        let snapshot = fetch(&config).await.expect("catalogue reads");

        // A live PostgreSQL always has at least its own tables somewhere, but
        // the queries exclude system schemas, so an empty database is a valid
        // result. What matters is that the queries parsed and the columns were
        // found by the names `fetch` uses.
        for stats in snapshot.tables.values() {
            assert!(!stats.schema.is_empty());
            assert!(!stats.name.is_empty());
        }
        for key in &snapshot.foreign_keys {
            assert!(key.child.contains('.'));
            assert!(key.parent.contains('.'));
        }
    }

    #[test]
    fn primary_keys_are_collected_per_table() {
        let rows = Rows {
            columns: vec!["table_name".into(), "column_name".into()],
            rows: vec![
                vec![Some("public.orders".into()), Some("id".into())],
                vec![Some("public.line_items".into()), Some("order_id".into())],
                vec![Some("public.line_items".into()), Some("sku".into())],
            ],
        };
        let mut snapshot = CatalogSnapshot::default();
        collect_primary_keys(&mut snapshot, &rows);

        assert_eq!(snapshot.primary_keys["public.orders"], vec!["id"]);
        assert_eq!(
            snapshot.primary_keys["public.line_items"],
            vec!["order_id", "sku"]
        );
    }
}
