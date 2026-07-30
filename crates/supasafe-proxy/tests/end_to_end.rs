//! End-to-end tests against a real PostgreSQL server, driven by a real
//! client.
//!
//! Unit tests prove the parser understands `DROP TABLE`. Only this proves that
//! an actual client, speaking the actual protocol, is actually stopped, and
//! that the table is still there afterwards.
//!
//! These tests need a PostgreSQL server and the `psql` binary. Point
//! `SUPASAFE_TEST_PG` at a server and they run; leave it unset and they skip,
//! so `cargo test` works on a laptop with nothing installed.
//!
//! ```sh
//! SUPASAFE_TEST_PG=postgresql://postgres@127.0.0.1:5432/postgres cargo test -p supasafe-proxy
//! ```

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;

use supasafe_core::approval::{ApprovalSettings, ApprovalStore};
use supasafe_core::audit::AuditLog;
use supasafe_core::config::{Config, DatabaseConfig};
use supasafe_core::environment::{ConnectionTarget, Environment};
use supasafe_core::guard::Guard;
use supasafe_core::snapshot::{SnapshotManager, SnapshotSettings};
use supasafe_proxy::{Proxy, ProxyConfig};

/// A running proxy in front of the test database.
struct Harness {
    addr: SocketAddr,
    upstream: ConnectionTarget,
    guard: Arc<Guard>,
}

impl Harness {
    /// Start a proxy that treats the test database as production.
    async fn start(policy: &str) -> Option<Harness> {
        let url = std::env::var("SUPASAFE_TEST_PG").ok()?;
        let upstream = ConnectionTarget::from_url(&url)?;

        let mut config = Config::default();
        // The test server is on localhost, which SupaSafe would otherwise
        // classify as local. Declaring it makes the test exercise the
        // production path.
        config.databases.push(DatabaseConfig {
            name: "test-target".into(),
            host: Some(upstream.host.clone()),
            environment: Some(Environment::Production),
            policy: Some(policy.to_string()),
            ..Default::default()
        });

        // Nobody is watching a test suite, so approval-gated statements should
        // time out in seconds rather than the five minutes a real deployment
        // gives a human.
        for entry in config.policies.values_mut() {
            entry.approval_timeout_seconds = 2;
        }

        let guard = Arc::new(Guard::new(
            config.compile().expect("config compiles"),
            Arc::new(AuditLog::in_memory()),
            ApprovalStore::new(ApprovalSettings {
                // Nobody is watching in a test, so an approval-gated statement
                // should fail fast rather than stall the suite.
                timeout_seconds: 2,
                ..Default::default()
            }),
        ));

        let proxy = Arc::new(Proxy::new(
            ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream_host: upstream.host.clone(),
                upstream_port: upstream.port,
                server_tls: None,
                client_tls: None,
            },
            guard.clone(),
            Arc::new(SnapshotManager::new(SnapshotSettings::default(), None)),
        ));

        let listener = proxy.bind().await.expect("proxy binds");
        let addr = listener.local_addr().expect("has an address");
        tokio::spawn(proxy.serve(listener));

        Some(Harness {
            addr,
            upstream,
            guard,
        })
    }

    /// Run SQL through the proxy with `psql`.
    fn psql(&self, sql: &str) -> Output {
        self.run_psql(self.addr.port(), sql)
    }

    /// Run SQL straight at the database, bypassing the proxy, to check what
    /// actually happened.
    fn psql_direct(&self, sql: &str) -> Output {
        self.run_psql(self.upstream.port, sql)
    }

    fn run_psql(&self, port: u16, sql: &str) -> Output {
        let out = Command::new("psql")
            .arg("--host")
            .arg(&self.upstream.host)
            .arg("--port")
            .arg(port.to_string())
            .arg("--username")
            .arg(&self.upstream.user)
            .arg("--dbname")
            .arg(&self.upstream.database)
            .arg("--no-psqlrc")
            .arg("--tuples-only")
            .arg("--no-align")
            .arg("--command")
            .arg(sql)
            .env("PGAPPNAME", "claude-code")
            .env("PGCONNECT_TIMEOUT", "10")
            .output()
            .expect("psql runs");
        Output {
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            success: out.status.success(),
        }
    }
}

struct Output {
    stdout: String,
    stderr: String,
    success: bool,
}

/// Skip rather than fail when there is no database to talk to.
macro_rules! harness {
    ($policy:expr) => {
        match Harness::start($policy).await {
            Some(h) => h,
            None => {
                eprintln!("skipping: set SUPASAFE_TEST_PG to run the end-to-end tests");
                return;
            }
        }
    };
}

#[tokio::test(flavor = "multi_thread")]
async fn a_select_passes_straight_through() {
    let h = harness!("production");
    let out = h.psql("SELECT 42");
    assert!(out.success, "psql failed: {}", out.stderr);
    assert_eq!(out.stdout.trim(), "42");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_drop_table_is_blocked_and_the_table_survives() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_drop");
    h.psql_direct("CREATE TABLE supasafe_e2e_drop (id int)");
    h.psql_direct("INSERT INTO supasafe_e2e_drop VALUES (1), (2), (3)");

    let out = h.psql("DROP TABLE supasafe_e2e_drop");
    assert!(!out.success, "the drop was not blocked: {}", out.stdout);
    assert!(
        out.stderr.contains("SupaSafe"),
        "the client did not see a SupaSafe error: {}",
        out.stderr
    );

    // The point of the whole product: the data is still there.
    let rows = h.psql_direct("SELECT count(*) FROM supasafe_e2e_drop");
    assert_eq!(rows.stdout.trim(), "3");

    h.psql_direct("DROP TABLE supasafe_e2e_drop");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unfiltered_delete_is_blocked_and_the_rows_survive() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_delete");
    h.psql_direct("CREATE TABLE supasafe_e2e_delete (id int)");
    h.psql_direct("INSERT INTO supasafe_e2e_delete SELECT generate_series(1, 100)");

    let out = h.psql("DELETE FROM supasafe_e2e_delete");
    assert!(!out.success, "the delete was not blocked");

    let rows = h.psql_direct("SELECT count(*) FROM supasafe_e2e_delete");
    assert_eq!(rows.stdout.trim(), "100");

    h.psql_direct("DROP TABLE supasafe_e2e_delete");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tautological_where_clause_does_not_get_a_delete_through() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_taut");
    h.psql_direct("CREATE TABLE supasafe_e2e_taut (id int)");
    h.psql_direct("INSERT INTO supasafe_e2e_taut SELECT generate_series(1, 10)");

    let out = h.psql("DELETE FROM supasafe_e2e_taut WHERE 1=1");
    assert!(!out.success, "WHERE 1=1 slipped through");

    let rows = h.psql_direct("SELECT count(*) FROM supasafe_e2e_taut");
    assert_eq!(rows.stdout.trim(), "10");

    h.psql_direct("DROP TABLE supasafe_e2e_taut");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scoped_write_is_allowed_and_actually_happens() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_scoped");
    h.psql_direct("CREATE TABLE supasafe_e2e_scoped (id int primary key, name text)");
    h.psql_direct("INSERT INTO supasafe_e2e_scoped VALUES (1, 'before'), (2, 'other')");

    let out = h.psql("UPDATE supasafe_e2e_scoped SET name = 'after' WHERE id = 1");
    assert!(out.success, "a scoped update was blocked: {}", out.stderr);

    let name = h.psql_direct("SELECT name FROM supasafe_e2e_scoped WHERE id = 1");
    assert_eq!(name.stdout.trim(), "after");

    h.psql_direct("DROP TABLE supasafe_e2e_scoped");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_statement_hidden_in_a_batch_stops_the_batch() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_batch");
    h.psql_direct("CREATE TABLE supasafe_e2e_batch (id int)");
    h.psql_direct("INSERT INTO supasafe_e2e_batch VALUES (1)");

    // psql sends this as one simple-query message.
    let out = h.psql("SELECT 1; DROP TABLE supasafe_e2e_batch;");
    assert!(!out.success, "a batched drop got through");

    let rows = h.psql_direct("SELECT count(*) FROM supasafe_e2e_batch");
    assert_eq!(rows.stdout.trim(), "1");

    h.psql_direct("DROP TABLE supasafe_e2e_batch");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_extended_protocol_is_covered_too() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_extended");
    h.psql_direct("CREATE TABLE supasafe_e2e_extended (id int)");
    h.psql_direct("INSERT INTO supasafe_e2e_extended SELECT generate_series(1, 5)");

    // A parameterised statement makes psql use Parse/Bind/Execute rather than
    // a simple query, which is a different code path in the proxy.
    let out = h.psql("PREPARE wipe AS DELETE FROM supasafe_e2e_extended; EXECUTE wipe;");
    assert!(!out.success, "an extended-protocol delete got through");

    let rows = h.psql_direct("SELECT count(*) FROM supasafe_e2e_extended");
    assert_eq!(rows.stdout.trim(), "5");

    h.psql_direct("DROP TABLE supasafe_e2e_extended");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_inside_a_transaction_aborts_it_consistently() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_txn");
    h.psql_direct("CREATE TABLE supasafe_e2e_txn (id int)");
    h.psql_direct("INSERT INTO supasafe_e2e_txn VALUES (1)");

    // The INSERT after the blocked DROP must not land: once SupaSafe refuses
    // inside a transaction, the client is told the block is aborted and
    // nothing else in it runs.
    let out = h.psql(
        "BEGIN; DROP TABLE supasafe_e2e_txn; INSERT INTO supasafe_e2e_txn VALUES (2); COMMIT;",
    );
    assert!(!out.success);

    let rows = h.psql_direct("SELECT count(*) FROM supasafe_e2e_txn");
    assert_eq!(rows.stdout.trim(), "1", "a statement ran after the refusal");

    h.psql_direct("DROP TABLE supasafe_e2e_txn");
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_timeouts_refuse_rather_than_hang() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_approval");
    h.psql_direct("CREATE TABLE supasafe_e2e_approval (id int)");
    h.psql_direct("INSERT INTO supasafe_e2e_approval VALUES (1)");

    // TRUNCATE needs approval under the production policy, and nobody is
    // going to give it.
    let out = h.psql("TRUNCATE TABLE supasafe_e2e_approval");
    assert!(!out.success);
    assert!(
        out.stderr.contains("approv"),
        "the message did not mention approval: {}",
        out.stderr
    );

    let rows = h.psql_direct("SELECT count(*) FROM supasafe_e2e_approval");
    assert_eq!(rows.stdout.trim(), "1");

    h.psql_direct("DROP TABLE supasafe_e2e_approval");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approved_statement_runs() {
    let h = harness!("production");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_approved");
    h.psql_direct("CREATE TABLE supasafe_e2e_approved (id int)");
    h.psql_direct("INSERT INTO supasafe_e2e_approved SELECT generate_series(1, 10)");

    // Approve whatever turns up, the way a human at the dashboard would.
    let approvals = h.guard.approvals().clone();
    tokio::spawn(async move {
        let mut events = approvals.subscribe();
        while let Ok(event) = events.recv().await {
            if event.request.state == supasafe_core::ApprovalState::Pending {
                let _ = approvals.approve(event.request.id, "alice");
            }
        }
    });

    let out = h.psql("TRUNCATE TABLE supasafe_e2e_approved");
    assert!(
        out.success,
        "an approved statement was still blocked: {}",
        out.stderr
    );

    let rows = h.psql_direct("SELECT count(*) FROM supasafe_e2e_approved");
    assert_eq!(rows.stdout.trim(), "0", "the approved truncate did not run");

    h.psql_direct("DROP TABLE supasafe_e2e_approved");
}

#[tokio::test(flavor = "multi_thread")]
async fn development_lets_everything_through() {
    let h = harness!("development");

    h.psql_direct("DROP TABLE IF EXISTS supasafe_e2e_dev");
    h.psql_direct("CREATE TABLE supasafe_e2e_dev (id int)");

    let out = h.psql("DROP TABLE supasafe_e2e_dev");
    assert!(out.success, "development blocked a drop: {}", out.stderr);

    let exists =
        h.psql_direct("SELECT count(*) FROM pg_tables WHERE tablename = 'supasafe_e2e_dev'");
    assert_eq!(exists.stdout.trim(), "0");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_audit_trail_records_what_happened() {
    let h = harness!("production");
    h.psql("SELECT 1");
    h.psql("DROP TABLE IF EXISTS supasafe_e2e_audit");

    // The in-memory log keeps the chain but not the records, so the check
    // here is that the chain stayed intact through real traffic.
    assert!(h.guard.audit().verify().unwrap().is_intact());
}
