//! The HTTP API behind the dashboard, the CLI and the VS Code extension.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::time::Duration;
use uuid::Uuid;

use supasafe_core::approval::ApprovalError;
use supasafe_core::environment::ConnectionTarget;
use supasafe_core::guard::Request as GuardRequest;

use crate::AppState;

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": supasafe_core::VERSION,
    }))
}

/// Everything the dashboard header needs in one request.
pub async fn summary(State(state): State<AppState>) -> Json<Value> {
    let approvals = state.guard.approvals();
    let records = state.guard.audit().records().unwrap_or_default();

    let blocked = records
        .iter()
        .filter(|r| matches!(r.outcome, supasafe_core::audit::Outcome::Blocked))
        .count();
    let executed = records
        .iter()
        .filter(|r| matches!(r.outcome, supasafe_core::audit::Outcome::Executed))
        .count();
    let highest_risk = records.iter().map(|r| r.risk).max().unwrap_or(0);

    // The timeline the dashboard draws: risk over the last 100 statements.
    let timeline: Vec<Value> = records
        .iter()
        .rev()
        .take(100)
        .rev()
        .map(|r| {
            json!({
                "at": r.timestamp,
                "risk": r.risk,
                "kind": r.statement_kind,
                "decision": r.decision.as_str(),
                "outcome": r.outcome.as_str(),
            })
        })
        .collect();

    Json(json!({
        "version": supasafe_core::VERSION,
        "statements": records.len(),
        "blocked": blocked,
        "executed": executed,
        "highest_risk": highest_risk,
        "pending_approvals": approvals.pending().len(),
        "policies": state.guard.config().policy_names(),
        "has_catalog": state.guard.has_catalog(),
        "audit_intact": state
            .guard
            .audit()
            .verify()
            .map(|v| v.is_intact())
            .unwrap_or(false),
        "timeline": timeline,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// How many records to return, newest first.
    #[serde(default = "default_limit")]
    limit: usize,
    /// Only records whose decision matches, e.g. `deny`.
    decision: Option<String>,
    /// Only records at or above this risk score.
    min_risk: Option<u8>,
}

fn default_limit() -> usize {
    100
}

pub async fn audit(State(state): State<AppState>, Query(query): Query<AuditQuery>) -> Json<Value> {
    let mut records = state.guard.audit().records().unwrap_or_default();
    records.reverse();

    let filtered: Vec<_> = records
        .into_iter()
        .filter(|r| {
            query
                .decision
                .as_ref()
                .map(|d| r.decision.as_str() == d)
                .unwrap_or(true)
        })
        .filter(|r| query.min_risk.map(|m| r.risk >= m).unwrap_or(true))
        .take(query.limit.min(1000))
        .collect();

    Json(json!({ "records": filtered }))
}

pub async fn verify_audit(State(state): State<AppState>) -> Json<Value> {
    match state.guard.audit().verify() {
        Ok(v) => Json(json!({
            "intact": v.is_intact(),
            "records": v.records,
            "head": v.head,
            "breaks": v.breaks,
        })),
        Err(e) => Json(json!({ "intact": false, "error": e.to_string() })),
    }
}

pub async fn approvals(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "approvals": state.guard.approvals().list() }))
}

pub async fn approval(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    state
        .guard
        .approvals()
        .get(id)
        .map(|r| Json(json!(r)))
        .ok_or(ApiError::NotFound)
}

#[derive(Debug, Deserialize)]
pub struct Decide {
    /// Who is answering. Recorded in the audit trail.
    approver: String,
    reason: Option<String>,
    sql: Option<String>,
}

pub async fn approve(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<Decide>,
) -> Result<Json<Value>, ApiError> {
    let updated = state.guard.approvals().approve(id, &body.approver)?;
    Ok(Json(json!(updated)))
}

pub async fn reject(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<Decide>,
) -> Result<Json<Value>, ApiError> {
    let updated = state
        .guard
        .approvals()
        .reject(id, &body.approver, body.reason)?;
    Ok(Json(json!(updated)))
}

pub async fn edit(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<Decide>,
) -> Result<Json<Value>, ApiError> {
    let sql = body
        .sql
        .ok_or_else(|| ApiError::BadRequest("an edited statement is required".into()))?;
    let updated = state.guard.approvals().edit(id, &body.approver, &sql)?;
    Ok(Json(json!(updated)))
}

pub async fn policies(State(state): State<AppState>) -> Json<Value> {
    let config = state.guard.config();
    let policies: Vec<Value> = config
        .policies()
        .map(|p| {
            json!({
                "name": p.name(),
                "description": p.policy.description,
                "default": p.policy.default,
                "warn_above": p.policy.warn_above,
                "require_approval_above": p.policy.require_approval_above,
                "deny_above": p.policy.deny_above,
                "approvals_required": p.policy.approvals_required,
                "snapshot_above": p.policy.snapshot_above,
                "protects_managed_surfaces": p.policy.protect_managed_surfaces,
                "denies_unparsed": p.policy.deny_unparsed,
                "rules": p.policy.rules.iter().map(|r| json!({
                    "name": r.name,
                    "action": r.action,
                    "message": r.message,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json!({ "policies": policies }))
}

#[derive(Debug, Deserialize)]
pub struct AnalyzeBody {
    sql: String,
    /// Judge the statement as if it were going to this host.
    host: Option<String>,
    database: Option<String>,
    agent: Option<String>,
}

/// Judge a statement without running it. This is what the "what would happen
/// if..." box in the dashboard calls, and what the VS Code extension uses to
/// check a selection.
pub async fn analyze(State(state): State<AppState>, Json(body): Json<AnalyzeBody>) -> Json<Value> {
    let target = ConnectionTarget {
        host: body.host.unwrap_or_default(),
        port: 5432,
        database: body.database.unwrap_or_else(|| "postgres".into()),
        user: String::new(),
        application_name: body.agent.clone(),
    };

    let request = GuardRequest {
        sql: body.sql,
        agent: body.agent.unwrap_or_else(|| "dashboard".into()),
        ..Default::default()
    };
    let verdict = state.guard.evaluate(&request, &target);

    Json(json!({
        "environment": verdict.environment.environment.as_str(),
        "environment_signals": verdict.environment.signals,
        "environment_assumed": verdict.environment.assumed,
        "policy": verdict.policy,
        "decision": verdict.decision.as_str(),
        "would_be_blocked": verdict.blocks_execution(),
        "risk": verdict.risk,
        "message": verdict.message(),
        "statements": verdict.statements.iter().map(|s| json!({
            "sql": s.statement.normalized,
            "kind": s.statement.kind.as_str(),
            "description": s.statement.describe(),
            "risk": s.risk,
            "decision": s.decision.as_str(),
            "rule": s.rule,
            "reasons": s.reasons,
            "objects": s.statement.objects.iter().map(|o| o.qualified()).collect::<Vec<_>>(),
            "blast": {
                "summary": s.blast.summary(),
                "rows_affected": s.blast.rows_affected.describe(),
                "heaviest_lock": s.blast.heaviest_lock.as_str(),
                "warnings": s.blast.warnings,
            },
            "rollback": {
                "reversibility": s.rollback.reversibility.as_str(),
                "summary": s.rollback.summary(),
                "steps": s.rollback.steps,
                "caveats": s.rollback.caveats,
            },
        })).collect::<Vec<_>>(),
    }))
}

/// Live approval events, so a held statement appears on screen immediately.
pub async fn stream(
    State(state): State<AppState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let mut events = state.guard.approvals().subscribe();

    let stream = async_stream::stream! {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event.request).unwrap_or_default();
                    yield Ok(Event::default().event("approval").data(data));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// API-level errors, mapped onto the status codes a client expects.
#[derive(Debug)]
pub enum ApiError {
    NotFound,
    BadRequest(String),
    Conflict(String),
}

impl From<ApprovalError> for ApiError {
    fn from(e: ApprovalError) -> ApiError {
        match e {
            ApprovalError::NotFound(_) => ApiError::NotFound,
            other => ApiError::Conflict(other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                "no approval request with that id".to_string(),
            ),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
