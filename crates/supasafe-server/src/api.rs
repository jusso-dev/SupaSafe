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
use supasafe_core::config::ConfigError;
use supasafe_core::environment::ConnectionTarget;
use supasafe_core::guard::Request as GuardRequest;
use supasafe_core::policy::{Matcher, PolicyError, Rule};

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
    let policies: Vec<Value> = config.policies().map(describe_policy).collect();
    Json(json!({
        "policies": policies,
        // The dashboard greys out its editor when there is nowhere to save to,
        // rather than letting somebody make changes that vanish on restart.
        "editable": state.editing_allowed && state.guard.config_path().is_some(),
        "config_path": state.guard.config_path().map(|p| p.display().to_string()),
        "editing_allowed": state.editing_allowed,
    }))
}

fn describe_policy(p: &supasafe_core::policy::CompiledPolicy) -> Value {
    json!({
        "name": p.name(),
        "description": p.policy.description,
        "default": p.policy.default,
        "warn_above": p.policy.warn_above,
        "require_approval_above": p.policy.require_approval_above,
        "deny_above": p.policy.deny_above,
        "approvals_required": p.policy.approvals_required,
        "snapshot_above": p.policy.snapshot_above,
        "dry_run_above": p.policy.dry_run_above,
        "approval_timeout_seconds": p.policy.approval_timeout_seconds,
        "protect_managed_surfaces": p.policy.protect_managed_surfaces,
        "deny_unparsed": p.policy.deny_unparsed,
        "rules": p.policy.rules.iter().enumerate().map(|(i, r)| json!({
            "index": i,
            "name": r.name,
            "action": r.action,
            "approvals": r.approvals,
            "message": r.message,
            "when": r.when,
        })).collect::<Vec<_>>(),
    })
}

/// The vocabulary a rule can be written in.
///
/// The dashboard builds its dropdowns from this rather than hard-coding a list
/// that drifts out of date the moment a statement kind is added.
pub async fn vocabulary() -> Json<Value> {
    use supasafe_parser::{Flags, StatementKind};

    let kinds: Vec<Value> = StatementKind::all()
        .iter()
        .map(|k| {
            json!({
                "id": k.as_str(),
                "label": k.label(),
                "category": k.category().as_str(),
            })
        })
        .collect();

    // Every flag name, taken from a Flags value with everything switched on, so
    // this cannot fall behind the struct.
    let all_flags = Flags {
        cascade: true,
        if_exists: true,
        or_replace: true,
        concurrently: true,
        only: true,
        drops_column: true,
        drops_constraint: true,
        changes_column_type: true,
        sets_not_null: true,
        changes_owner: true,
        adds_column: true,
        renames: true,
        weakens_rls: true,
        strengthens_rls: true,
        disables_trigger: true,
        grants_elevated_role: true,
        grants_all: true,
        grants_to_public: true,
        copy_program: true,
        copy_file: true,
        security_definer: true,
        opaque_body: true,
        opaque_body_is_destructive: true,
        returning: true,
        multi_table: true,
        locking_read: true,
        select_into: true,
        unparsed: true,
    };

    Json(json!({
        "kinds": kinds,
        "categories": ["read", "write", "ddl", "dcl", "maintenance", "transaction", "session", "execute", "unknown"],
        "actions": ["allow", "warn", "require_approval", "deny"],
        "flags": all_flags.active(),
        "levels": ["none", "low", "moderate", "high", "critical", "catastrophic"],
        "surfaces": [
            "supabase_auth", "supabase_storage", "supabase_realtime", "supabase_vault",
            "supabase_migrations", "supabase_functions", "supabase_graphql",
            "supabase_extensions", "supabase_jobs", "system_catalog", "user"
        ],
        "environments": ["local", "development", "staging", "production"],
    }))
}

/// A rule as the dashboard sends it.
#[derive(Debug, Deserialize)]
pub struct RuleBody {
    pub name: String,
    pub action: String,
    #[serde(default)]
    pub approvals: Option<u8>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub when: Matcher,
    /// Where to put it. Defaults to the front, because the first match wins.
    #[serde(default)]
    pub at: Option<usize>,
}

impl RuleBody {
    fn into_rule(self) -> Rule {
        Rule {
            name: self.name,
            action: self.action,
            approvals: self.approvals,
            message: self.message,
            when: self.when,
        }
    }
}

pub async fn add_rule(
    State(state): State<AppState>,
    Path(policy): Path<String>,
    Json(body): Json<RuleBody>,
) -> Result<Json<Value>, ApiError> {
    state.require_editable()?;
    let at = body.at;
    let rule = body.into_rule();
    state
        .guard
        .edit_config(|config| {
            config
                .add_rule(&policy, rule, at)
                .map_err(|e| ConfigError::Policy(PolicyError::Rejected(e.to_string())))
        })
        .map_err(edit_failed)?;
    Ok(Json(current_policy(&state, &policy)))
}

pub async fn update_rule(
    State(state): State<AppState>,
    Path((policy, index)): Path<(String, usize)>,
    Json(body): Json<RuleBody>,
) -> Result<Json<Value>, ApiError> {
    state.require_editable()?;
    let rule = body.into_rule();
    state
        .guard
        .edit_config(|config| {
            config
                .update_rule(&policy, index, rule)
                .map_err(|e| ConfigError::Policy(PolicyError::Rejected(e.to_string())))
        })
        .map_err(edit_failed)?;
    Ok(Json(current_policy(&state, &policy)))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Path((policy, index)): Path<(String, usize)>,
) -> Result<Json<Value>, ApiError> {
    state.require_editable()?;
    state
        .guard
        .edit_config(|config| {
            config
                .remove_rule(&policy, index)
                .map(|_| ())
                .map_err(|e| ConfigError::Policy(PolicyError::Rejected(e.to_string())))
        })
        .map_err(edit_failed)?;
    Ok(Json(current_policy(&state, &policy)))
}

#[derive(Debug, Deserialize)]
pub struct MoveBody {
    pub to: usize,
}

pub async fn move_rule(
    State(state): State<AppState>,
    Path((policy, index)): Path<(String, usize)>,
    Json(body): Json<MoveBody>,
) -> Result<Json<Value>, ApiError> {
    state.require_editable()?;
    state
        .guard
        .edit_config(|config| {
            config
                .move_rule(&policy, index, body.to)
                .map_err(|e| ConfigError::Policy(PolicyError::Rejected(e.to_string())))
        })
        .map_err(edit_failed)?;
    Ok(Json(current_policy(&state, &policy)))
}

/// The thresholds and guards, without touching the rules.
#[derive(Debug, Deserialize)]
pub struct SettingsBody {
    pub description: Option<String>,
    pub default: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub warn_above: Option<Option<u8>>,
    #[serde(default, deserialize_with = "double_option")]
    pub require_approval_above: Option<Option<u8>>,
    #[serde(default, deserialize_with = "double_option")]
    pub deny_above: Option<Option<u8>>,
    #[serde(default, deserialize_with = "double_option")]
    pub snapshot_above: Option<Option<u8>>,
    #[serde(default, deserialize_with = "double_option")]
    pub dry_run_above: Option<Option<u8>>,
    pub approvals_required: Option<u8>,
    pub approval_timeout_seconds: Option<u64>,
    pub deny_unparsed: Option<bool>,
    pub protect_managed_surfaces: Option<bool>,
}

/// Distinguish "absent" from "explicitly null", so the dashboard can clear a
/// threshold rather than only ever setting one.
fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

pub async fn update_settings(
    State(state): State<AppState>,
    Path(policy): Path<String>,
    Json(body): Json<SettingsBody>,
) -> Result<Json<Value>, ApiError> {
    state.require_editable()?;
    state
        .guard
        .edit_config(|config| {
            let target = config
                .policy_mut(&policy)
                .ok_or_else(|| ConfigError::Policy(PolicyError::Unknown(policy.clone())))?;
            if let Some(v) = body.description {
                target.description = v;
            }
            if let Some(v) = body.default {
                target.default = v;
            }
            if let Some(v) = body.warn_above {
                target.warn_above = v;
            }
            if let Some(v) = body.require_approval_above {
                target.require_approval_above = v;
            }
            if let Some(v) = body.deny_above {
                target.deny_above = v;
            }
            if let Some(v) = body.snapshot_above {
                target.snapshot_above = v;
            }
            if let Some(v) = body.dry_run_above {
                target.dry_run_above = v;
            }
            if let Some(v) = body.approvals_required {
                target.approvals_required = v.max(1);
            }
            if let Some(v) = body.approval_timeout_seconds {
                target.approval_timeout_seconds = v;
            }
            if let Some(v) = body.deny_unparsed {
                target.deny_unparsed = v;
            }
            if let Some(v) = body.protect_managed_surfaces {
                target.protect_managed_surfaces = v;
            }
            Ok(())
        })
        .map_err(edit_failed)?;
    Ok(Json(current_policy(&state, &policy)))
}

/// Try a rule out before saving it.
///
/// Takes a draft rule and some SQL, and reports what would happen with the
/// draft in place and what happens without it. Tuning a rule you cannot try is
/// guesswork, and guessing about a deny rule in production is how you find out
/// it matched more than you meant.
#[derive(Debug, Deserialize)]
pub struct TryRuleBody {
    pub sql: String,
    /// The policy to try it against.
    pub policy: String,
    /// The draft rule. Omit to test the policy as it stands.
    #[serde(default)]
    pub rule: Option<RuleBody>,
    pub host: Option<String>,
    pub agent: Option<String>,
}

pub async fn try_rule(
    State(state): State<AppState>,
    Json(mut body): Json<TryRuleBody>,
) -> Result<Json<Value>, ApiError> {
    let mut draft = state.guard.config().config.clone();

    // Force the requested policy so the test is not at the mercy of whatever
    // the host name happens to look like.
    draft.databases.insert(
        0,
        supasafe_core::config::DatabaseConfig {
            name: "__try_rule".into(),
            host: Some("*".into()),
            policy: Some(body.policy.clone()),
            environment: draft
                .policies
                .get(&body.policy)
                .and_then(|_| environment_for_policy(&body.policy)),
            ..Default::default()
        },
    );

    let before = evaluate_with(&draft, &body).map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let after = match body.rule.take() {
        Some(rule) => {
            let at = rule.at;
            draft
                .add_rule(&body.policy, rule.into_rule(), at)
                .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            Some(evaluate_with(&draft, &body).map_err(|e| ApiError::BadRequest(e.to_string()))?)
        }
        None => None,
    };

    Ok(Json(json!({
        "without_rule": before,
        "with_rule": after,
        "changed": after.as_ref().map(|a| a["decision"] != before["decision"]).unwrap_or(false),
    })))
}

fn environment_for_policy(name: &str) -> Option<supasafe_core::Environment> {
    use supasafe_core::Environment;
    match name {
        "development" => Some(Environment::Development),
        "staging" => Some(Environment::Staging),
        _ => Some(Environment::Production),
    }
}

fn evaluate_with(
    config: &supasafe_core::config::Config,
    body: &TryRuleBody,
) -> Result<Value, supasafe_core::config::ConfigError> {
    let compiled = config.compile()?;
    let guard = supasafe_core::guard::Guard::new(
        compiled,
        std::sync::Arc::new(supasafe_core::audit::AuditLog::in_memory()),
        supasafe_core::approval::ApprovalStore::new(Default::default()),
    );

    let target = ConnectionTarget {
        host: body.host.clone().unwrap_or_else(|| "db.example.com".into()),
        port: 5432,
        database: "postgres".into(),
        user: String::new(),
        application_name: body.agent.clone(),
    };
    let request = GuardRequest {
        sql: body.sql.clone(),
        agent: body.agent.clone().unwrap_or_else(|| "dashboard".into()),
        ..Default::default()
    };
    let verdict = guard.evaluate(&request, &target);

    Ok(json!({
        "decision": verdict.decision.as_str(),
        "would_be_blocked": verdict.blocks_execution(),
        "risk": verdict.risk,
        "environment": verdict.environment.environment.as_str(),
        "statements": verdict.statements.iter().map(|s| json!({
            "description": s.statement.describe(),
            "kind": s.statement.kind.as_str(),
            "risk": s.risk.score,
            "decision": s.decision.as_str(),
            "matched_rule": s.rule,
            "reasons": s.reasons,
        })).collect::<Vec<_>>(),
    }))
}

/// Re-read the configuration from disk, for when somebody edited the file by
/// hand while the proxy was running.
pub async fn reload_config(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    state
        .guard
        .reload_config()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(json!({
        "reloaded": true,
        "config_path": state.guard.config_path().map(|p| p.display().to_string()),
        "policies": state.guard.config().policy_names(),
    })))
}

/// The configuration as TOML, for the raw editor.
pub async fn get_config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "toml": state.guard.config().config.to_toml(),
        "path": state.guard.config_path().map(|p| p.display().to_string()),
        "editable": state.editing_allowed && state.guard.config_path().is_some(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ConfigBody {
    pub toml: String,
}

/// Replace the whole configuration from TOML.
///
/// Parsed and compiled before anything is installed or written, so a typo is a
/// 400 rather than a proxy that has forgotten its policies.
pub async fn put_config(
    State(state): State<AppState>,
    Json(body): Json<ConfigBody>,
) -> Result<Json<Value>, ApiError> {
    state.require_editable()?;

    let parsed = supasafe_core::config::Config::parse(&body.toml)
        .map_err(|e| ApiError::BadRequest(format!("that is not valid configuration: {e}")))?;

    state
        .guard
        .edit_config(|config| {
            *config = parsed.clone();
            Ok(())
        })
        .map_err(edit_failed)?;

    Ok(Json(json!({
        "saved": true,
        "policies": state.guard.config().policy_names(),
    })))
}

fn current_policy(state: &AppState, name: &str) -> Value {
    let config = state.guard.config();
    match config.policy(name) {
        Some(p) => json!({ "policy": describe_policy(p) }),
        None => json!({ "policy": Value::Null }),
    }
}

fn edit_failed(e: ConfigError) -> ApiError {
    ApiError::BadRequest(e.to_string())
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
    Forbidden(String),
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
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
