//! # supasafe-server
//!
//! The dashboard and the approval API.
//!
//! When a statement is held, somebody has to see it. This serves the page they
//! look at, the endpoints they answer on, and a live event stream so a request
//! appears the moment it is raised rather than on the next refresh.
//!
//! It binds to loopback by default. The approval endpoint is the one thing in
//! SupaSafe that can turn a refusal into an execution, so exposing it to a
//! network is a decision an operator has to make deliberately.

#![forbid(unsafe_code)]

pub mod api;
mod ui;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post, put};
use axum::Router;
use tower_http::cors::CorsLayer;

use supasafe_core::guard::Guard;

/// Shared state for every handler.
#[derive(Clone)]
pub struct AppState {
    pub guard: Arc<Guard>,
    /// Whether policy rules can be changed through the API.
    ///
    /// Editing a rule changes what the proxy lets through, immediately. That is
    /// the point of having it, and it is also why an operator who exposes the
    /// dashboard beyond loopback may want it off.
    pub editing_allowed: bool,
}

impl AppState {
    /// Reject an edit when editing is switched off.
    pub fn require_editable(&self) -> Result<(), api::ApiError> {
        if !self.editing_allowed {
            return Err(api::ApiError::Forbidden(
                "policy editing is switched off. Set server.allow_policy_editing = true, or edit \
                 supasafe.toml directly."
                    .into(),
            ));
        }
        if self.guard.config_path().is_none() {
            return Err(api::ApiError::Forbidden(
                "SupaSafe has no configuration file to save to, so an edit made here would be \
                 lost on restart. Run `supasafe init` and start with --config."
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Build the router.
pub fn router(guard: Arc<Guard>) -> Router {
    router_with(guard, true)
}

/// Build the router, choosing whether policy editing is exposed.
pub fn router_with(guard: Arc<Guard>, editing_allowed: bool) -> Router {
    let state = AppState {
        guard,
        editing_allowed,
    };

    Router::new()
        .route("/", get(ui::index))
        .route("/health", get(api::health))
        .route("/api/summary", get(api::summary))
        .route("/api/audit", get(api::audit))
        .route("/api/audit/verify", get(api::verify_audit))
        .route("/api/approvals", get(api::approvals))
        .route("/api/approvals/{id}", get(api::approval))
        .route("/api/approvals/{id}/approve", post(api::approve))
        .route("/api/approvals/{id}/reject", post(api::reject))
        .route("/api/approvals/{id}/edit", post(api::edit))
        .route("/api/analyze", post(api::analyze))
        .route("/api/stream", get(api::stream))
        // --- policy tuning ------------------------------------------------
        .route("/api/policies", get(api::policies))
        .route("/api/policies/vocabulary", get(api::vocabulary))
        .route("/api/policies/try", post(api::try_rule))
        .route("/api/policies/{policy}/settings", put(api::update_settings))
        .route("/api/policies/{policy}/rules", post(api::add_rule))
        .route(
            "/api/policies/{policy}/rules/{index}",
            put(api::update_rule).delete(api::delete_rule),
        )
        .route(
            "/api/policies/{policy}/rules/{index}/move",
            post(api::move_rule),
        )
        .route("/api/config", get(api::get_config).put(api::put_config))
        .route("/api/config/reload", post(api::reload_config))
        // The dashboard is served from the same origin; CORS is here so a
        // separate front end or the VS Code extension can talk to the API.
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Serve until the process ends.
pub async fn serve(listen: SocketAddr, guard: Arc<Guard>) -> std::io::Result<()> {
    serve_with(listen, guard, true).await
}

/// Serve, choosing whether policy editing is exposed.
pub async fn serve_with(
    listen: SocketAddr,
    guard: Arc<Guard>,
    editing_allowed: bool,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, editing_allowed, "dashboard listening");
    axum::serve(listener, router_with(guard, editing_allowed)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{json, Value};
    use std::sync::Arc;
    use supasafe_core::approval::{ApprovalSettings, ApprovalStore};
    use supasafe_core::audit::AuditLog;
    use supasafe_core::config::Config;
    use supasafe_core::environment::ConnectionTarget;
    use supasafe_core::guard::Request as GuardRequest;
    use tower::ServiceExt;

    fn guard() -> Arc<Guard> {
        Arc::new(Guard::new(
            Config::default().compile().unwrap(),
            Arc::new(AuditLog::in_memory()),
            ApprovalStore::new(ApprovalSettings::default()),
        ))
    }

    async fn get(app: &Router, path: &str) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    async fn post_json(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    fn pending_approval(guard: &Arc<Guard>) -> uuid::Uuid {
        let target = ConnectionTarget::new("db.abcdefghijklmnopqrst.supabase.co", 5432, "postgres");
        let request = GuardRequest::new("TRUNCATE TABLE orders").from_agent("claude-code");
        let verdict = guard.evaluate(&request, &target);
        guard.request_approval(&verdict, &request, None).id
    }

    #[tokio::test]
    async fn the_dashboard_renders() {
        let app = router(guard());
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&bytes);
        assert!(html.contains("SupaSafe"));
        assert!(html.contains("<!doctype html>"));
    }

    #[tokio::test]
    async fn health_reports_ready() {
        let (status, body) = get(&router(guard()), "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn summary_counts_what_has_happened() {
        let g = guard();
        pending_approval(&g);
        let (status, body) = get(&router(g), "/api/summary").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["pending_approvals"], 1);
    }

    #[tokio::test]
    async fn approvals_are_listed_with_what_a_human_needs() {
        let g = guard();
        pending_approval(&g);
        let (_, body) = get(&router(g), "/api/approvals").await;
        let first = &body["approvals"][0];
        assert_eq!(first["agent"], "claude-code");
        assert!(first["description"].as_str().unwrap().contains("empty"));
        assert!(first["risk"]["score"].as_u64().unwrap() >= 95);
        assert_eq!(first["rollback"]["reversibility"], "irreversible");
    }

    #[tokio::test]
    async fn approving_records_the_approver() {
        let g = guard();
        let id = pending_approval(&g);
        let app = router(g.clone());
        let (status, body) = post_json(
            &app,
            &format!("/api/approvals/{id}/approve"),
            json!({ "approver": "alice" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"]["state"], "approved");
        assert_eq!(g.approvals().pending().len(), 0);
    }

    #[tokio::test]
    async fn an_approver_cannot_approve_their_own_request() {
        let g = guard();
        let id = pending_approval(&g);
        let app = router(g);
        let (status, body) = post_json(
            &app,
            &format!("/api/approvals/{id}/approve"),
            json!({ "approver": "claude-code" }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].as_str().unwrap().contains("own request"));
    }

    #[tokio::test]
    async fn rejecting_closes_the_request() {
        let g = guard();
        let id = pending_approval(&g);
        let app = router(g.clone());
        let (status, body) = post_json(
            &app,
            &format!("/api/approvals/{id}/reject"),
            json!({ "approver": "alice", "reason": "wrong table" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"]["state"], "rejected");
    }

    #[tokio::test]
    async fn editing_replaces_the_statement() {
        let g = guard();
        let id = pending_approval(&g);
        let app = router(g);
        let (status, body) = post_json(
            &app,
            &format!("/api/approvals/{id}/edit"),
            json!({ "approver": "alice", "sql": "DELETE FROM orders WHERE id = 1" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"]["state"], "edited");
    }

    #[tokio::test]
    async fn a_missing_approval_is_a_404() {
        let app = router(guard());
        let (status, _) = post_json(
            &app,
            &format!("/api/approvals/{}/approve", uuid::Uuid::new_v4()),
            json!({ "approver": "alice" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn policies_are_listed() {
        let (_, body) = get(&router(guard()), "/api/policies").await;
        let names: Vec<&str> = body["policies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"production"));
        assert!(names.contains(&"regulated"));
    }

    #[tokio::test]
    async fn analyze_judges_a_statement_without_running_it() {
        let app = router(guard());
        let (status, body) = post_json(
            &app,
            "/api/analyze",
            json!({ "sql": "DROP TABLE users", "host": "db.abcdefghijklmnopqrst.supabase.co" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["risk"], 100);
        assert_eq!(body["would_be_blocked"], true);
        assert_eq!(body["environment"], "production");
    }

    // --- policy tuning ----------------------------------------------------

    /// A guard whose configuration lives in a real file, so edits can be saved.
    fn editable_guard() -> (Arc<Guard>, std::path::PathBuf) {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "supasafe-editable-{}-{:?}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Config::default().save(&path).unwrap();
        let config = Config::load(&path).unwrap();
        let guard = Arc::new(
            Guard::new(
                config.compile().unwrap(),
                Arc::new(AuditLog::in_memory()),
                ApprovalStore::new(ApprovalSettings::default()),
            )
            .with_config_path(Some(path.clone())),
        );
        (guard, path)
    }

    async fn put_json(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
        send(app, "PUT", path, Some(body)).await
    }

    async fn delete(app: &Router, path: &str) -> (StatusCode, Value) {
        send(app, "DELETE", path, None).await
    }

    async fn send(
        app: &Router,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(match &body {
                Some(b) => Body::from(b.to_string()),
                None => Body::empty(),
            })
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// What the proxy would do with this statement, right now.
    fn decides(guard: &Arc<Guard>, sql: &str) -> String {
        let target = ConnectionTarget::new("db.abcdefghijklmnopqrst.supabase.co", 5432, "postgres");
        guard
            .evaluate(&GuardRequest::new(sql), &target)
            .decision
            .as_str()
            .to_string()
    }

    #[tokio::test]
    async fn the_rule_vocabulary_is_offered_to_the_editor() {
        let (_, body) = get(&router(guard()), "/api/policies/vocabulary").await;
        let kinds: Vec<&str> = body["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["id"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"drop_table"));
        let flags: Vec<&str> = body["flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap())
            .collect();
        assert!(flags.contains(&"weakens_rls"));
        assert!(flags.contains(&"copy_program"));
    }

    #[tokio::test]
    async fn adding_a_rule_changes_what_the_proxy_does_immediately() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        // A read is allowed to start with.
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "allow");

        let (status, _) = post_json(
            &app,
            "/api/policies/production/rules",
            json!({
                "name": "no-reads-of-secrets",
                "action": "deny",
                "message": "The secrets table is not for agents.",
                "when": { "objects": ["public.secrets"] }
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The very next statement is judged by the new rule.
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "deny");
        // And nothing else moved.
        assert_eq!(decides(&guard, "SELECT * FROM public.users"), "allow");

        // It survives a restart, because it was written to the file.
        let reloaded = Config::load(&path).unwrap();
        assert!(reloaded.policies["production"]
            .rules
            .iter()
            .any(|r| r.name == "no-reads-of-secrets"));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_rule_with_a_bad_glob_is_rejected_and_changes_nothing() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());
        let before = guard
            .config()
            .policy("production")
            .unwrap()
            .policy
            .rules
            .len();

        let (status, body) = post_json(
            &app,
            "/api/policies/production/rules",
            json!({ "name": "broken", "action": "deny", "when": { "objects": ["["] } }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("glob"));
        assert_eq!(
            guard
                .config()
                .policy("production")
                .unwrap()
                .policy
                .rules
                .len(),
            before,
            "a rejected rule was still installed"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn rules_can_be_reordered_and_order_decides() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        // Allow reads of a table that the built-in rules would otherwise let
        // through anyway, then put a deny in front of it.
        post_json(
            &app,
            "/api/policies/production/rules",
            json!({ "name": "allow-secrets", "action": "allow", "when": { "objects": ["public.secrets"] } }),
        )
        .await;
        post_json(
            &app,
            "/api/policies/production/rules",
            json!({ "name": "deny-secrets", "action": "deny", "when": { "objects": ["public.secrets"] } }),
        )
        .await;

        // deny-secrets was added last, so it is first, so it wins.
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "deny");

        // Move it below the allow and the outcome flips.
        let (status, _) = post_json(
            &app,
            "/api/policies/production/rules/0/move",
            json!({ "to": 1 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "allow");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_rule_can_be_edited_and_deleted() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        post_json(
            &app,
            "/api/policies/production/rules",
            json!({ "name": "secrets", "action": "deny", "when": { "objects": ["public.secrets"] } }),
        )
        .await;
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "deny");

        let (status, _) = put_json(
            &app,
            "/api/policies/production/rules/0",
            json!({ "name": "secrets", "action": "warn", "when": { "objects": ["public.secrets"] } }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "warn");

        let (status, _) = delete(&app, "/api/policies/production/rules/0").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "allow");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn thresholds_can_be_tuned() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        let (status, _) = put_json(
            &app,
            "/api/policies/staging/settings",
            json!({ "require_approval_above": 50 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            guard
                .config()
                .policy("staging")
                .unwrap()
                .policy
                .require_approval_above,
            Some(50)
        );

        // Explicit null clears it again, which a plain Option would not manage.
        put_json(
            &app,
            "/api/policies/staging/settings",
            json!({ "require_approval_above": null }),
        )
        .await;
        assert_eq!(
            guard
                .config()
                .policy("staging")
                .unwrap()
                .policy
                .require_approval_above,
            None
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_rule_can_be_tried_before_it_is_saved() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        let (status, body) = post_json(
            &app,
            "/api/policies/try",
            json!({
                "sql": "SELECT * FROM public.secrets",
                "policy": "production",
                "rule": { "name": "draft", "action": "deny", "when": { "objects": ["public.secrets"] } }
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["without_rule"]["decision"], "allow");
        assert_eq!(body["with_rule"]["decision"], "deny");
        assert_eq!(body["changed"], true);

        // Trying a rule must not install it.
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "allow");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn editing_is_refused_when_there_is_nowhere_to_save() {
        // The default test guard has no config file behind it.
        let app = router(guard());
        let (status, body) = post_json(
            &app,
            "/api/policies/production/rules",
            json!({ "name": "x", "action": "deny" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body["error"].as_str().unwrap().contains("restart"));
    }

    #[tokio::test]
    async fn editing_can_be_switched_off() {
        let (guard, path) = editable_guard();
        let app = router_with(guard, false);

        let (status, body) = post_json(
            &app,
            "/api/policies/production/rules",
            json!({ "name": "x", "action": "deny" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("allow_policy_editing"));

        // Reading is still fine.
        let (status, body) = get(&app, "/api/policies").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["editable"], false);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn the_whole_config_can_be_replaced_as_toml() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        let (status, _) = put_json(
            &app,
            "/api/config",
            json!({
                "toml": "[[policies.production.rules]]\n\
                         name = \"from-toml\"\n\
                         action = \"deny\"\n\
                         when = { objects = [\"public.secrets\"] }\n"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "deny");
        // Built-in rules survived, so ordinary traffic still flows.
        assert_eq!(decides(&guard, "SELECT * FROM public.users"), "allow");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn broken_toml_is_rejected_and_the_policy_survives() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        let (status, _) = put_json(
            &app,
            "/api/config",
            json!({ "toml": "this is not toml [[[" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(decides(&guard, "DROP TABLE users"), "require_approval");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_hand_edited_file_can_be_reloaded() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "allow");

        // Somebody edits the file directly, the way they would over ssh: a
        // short file with one rule in it, relying on the built-ins for the
        // rest.
        std::fs::write(
            &path,
            "[[policies.production.rules]]\nname = \"hand-written\"\naction = \"deny\"\n\
             when = { objects = [\"public.secrets\"] }\n",
        )
        .unwrap();

        let (status, _) = post_json(&app, "/api/config/reload", json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decides(&guard, "SELECT * FROM public.secrets"), "deny");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn protected_surfaces_stay_protected_through_an_edit() {
        let (guard, path) = editable_guard();
        let app = router(guard.clone());

        // Even a blanket allow rule does not open the auth schema, because the
        // managed-surface guard runs before the rules do.
        post_json(
            &app,
            "/api/policies/production/rules",
            json!({ "name": "allow-everything", "action": "allow" }),
        )
        .await;

        assert_eq!(decides(&guard, "DROP TABLE auth.users"), "deny");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn the_audit_endpoint_reports_chain_integrity() {
        let (status, body) = get(&router(guard()), "/api/audit/verify").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["intact"], true);
    }
}
