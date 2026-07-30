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

mod api;
mod ui;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;

use supasafe_core::guard::Guard;

/// Shared state for every handler.
#[derive(Clone)]
pub struct AppState {
    pub guard: Arc<Guard>,
}

/// Build the router.
pub fn router(guard: Arc<Guard>) -> Router {
    let state = AppState { guard };

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
        .route("/api/policies", get(api::policies))
        .route("/api/analyze", post(api::analyze))
        .route("/api/stream", get(api::stream))
        // The dashboard is served from the same origin; CORS is here so a
        // separate front end or the VS Code extension can talk to the API.
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Serve until the process ends.
pub async fn serve(listen: SocketAddr, guard: Arc<Guard>) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "dashboard listening");
    axum::serve(listener, router(guard)).await
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

    #[tokio::test]
    async fn the_audit_endpoint_reports_chain_integrity() {
        let (status, body) = get(&router(guard()), "/api/audit/verify").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["intact"], true);
    }
}
