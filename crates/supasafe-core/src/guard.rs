//! The guard: one request in, one verdict out.
//!
//! Everything else in this crate is a component. This is the thing the proxy,
//! the CLI and the MCP server all call, so that a statement gets the same
//! answer no matter which door it came through. There is exactly one place
//! where "should this run?" is decided.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use supasafe_parser::{analyze, Batch, StatementAnalysis};

use crate::approval::{deadline, ApprovalRequest, ApprovalState, ApprovalStore};
use crate::audit::{hash_prompt, AuditEntry, AuditLog, Outcome};
use crate::blast::{self, BlastRadius};
use crate::catalog::CatalogSnapshot;
use crate::config::CompiledConfig;
use crate::context;
use crate::environment::{ConnectionTarget, EnvironmentInfo};
use crate::policy::{Decision, MatchContext, PolicyOutcome};
use crate::risk::{self, RiskInput, RiskScore};
use crate::rollback::{self, RollbackPlan};

/// Who is asking, and about what.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub sql: String,
    /// From the client's `application_name`, e.g. `claude-code`.
    pub agent: String,
    /// The prompt behind the SQL, when the client passes one. Hashed
    /// immediately; never stored.
    pub prompt: Option<String>,
    /// A human-readable justification the agent supplied.
    pub reason: Option<String>,
    /// The connection is inside an explicit transaction.
    pub in_transaction: bool,
}

impl Request {
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            agent: "unknown".to_string(),
            ..Default::default()
        }
    }

    pub fn from_agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = agent.into();
        self
    }
}

/// The verdict for one statement in a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatementVerdict {
    pub statement: StatementAnalysis,
    pub risk: RiskScore,
    pub decision: Decision,
    pub rule: Option<String>,
    pub reasons: Vec<String>,
    pub blast: BlastRadius,
    pub rollback: RollbackPlan,
    /// The policy asked for a snapshot before this runs.
    pub wants_snapshot: bool,
    /// The policy asked for an EXPLAIN before this runs.
    pub wants_dry_run: bool,
}

impl StatementVerdict {
    /// A sentence explaining the outcome, suitable for returning to an agent
    /// as an error message.
    pub fn message(&self) -> String {
        context::refusal_message(
            &self.statement.describe(),
            &self.reasons,
            Some(&self.rollback.summary()),
        )
    }
}

/// The verdict for a whole request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub id: Uuid,
    /// The most severe decision across every statement. A batch is as safe as
    /// its worst statement.
    pub decision: Decision,
    pub statements: Vec<StatementVerdict>,
    pub environment: EnvironmentInfo,
    pub policy: String,
    /// The highest score in the batch.
    pub risk: u8,
}

impl Verdict {
    pub fn blocks_execution(&self) -> bool {
        self.decision.blocks_execution()
    }

    /// The statement responsible for the verdict.
    pub fn dominant(&self) -> Option<&StatementVerdict> {
        self.statements.iter().max_by(|a, b| {
            a.decision
                .cmp(&b.decision)
                .then(a.risk.score.cmp(&b.risk.score))
        })
    }

    /// The message to return to the client when a request is refused.
    pub fn message(&self) -> String {
        match self.dominant() {
            Some(s) => s.message(),
            None => "SupaSafe refused this request.".to_string(),
        }
    }

    /// Every object the request touches.
    pub fn affected_objects(&self) -> Vec<String> {
        let mut objects: Vec<String> = self
            .statements
            .iter()
            .flat_map(|s| s.statement.objects.iter().map(|o| o.qualified()))
            .collect();
        objects.sort();
        objects.dedup();
        objects
    }

    pub fn needs_approval(&self) -> bool {
        matches!(self.decision, Decision::RequireApproval { .. })
    }

    pub fn approvals_required(&self) -> u8 {
        match self.decision {
            Decision::RequireApproval { approvals } => approvals.max(1),
            _ => 0,
        }
    }
}

/// The component every entry point talks to.
pub struct Guard {
    config: CompiledConfig,
    audit: Arc<AuditLog>,
    approvals: ApprovalStore,
    catalog: RwLock<Option<CatalogSnapshot>>,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("policies", &self.config.policy_names())
            .field("has_catalog", &self.catalog.read().is_ok())
            .finish()
    }
}

impl Guard {
    pub fn new(config: CompiledConfig, audit: Arc<AuditLog>, approvals: ApprovalStore) -> Guard {
        Guard {
            config,
            audit,
            approvals,
            catalog: RwLock::new(None),
        }
    }

    pub fn config(&self) -> &CompiledConfig {
        &self.config
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn approvals(&self) -> &ApprovalStore {
        &self.approvals
    }

    /// Install a fresh catalogue snapshot. The proxy refreshes this in the
    /// background when it has an introspection connection.
    pub fn set_catalog(&self, catalog: CatalogSnapshot) {
        if let Ok(mut guard) = self.catalog.write() {
            *guard = Some(catalog);
        }
    }

    pub fn has_catalog(&self) -> bool {
        self.catalog
            .read()
            .map(|c| c.as_ref().map(|c| !c.is_empty()).unwrap_or(false))
            .unwrap_or(false)
    }

    /// Analyse and judge a request without executing anything or writing to
    /// the audit trail.
    pub fn evaluate(&self, request: &Request, target: &ConnectionTarget) -> Verdict {
        let info = self.config.classify(target);
        let policy = self.config.policy_for(&info);
        let batch: Batch = analyze(&request.sql);

        let catalog_guard = self.catalog.read().ok();
        let catalog = catalog_guard.as_ref().and_then(|c| c.as_ref());

        let mut statements = Vec::with_capacity(batch.statements.len());
        let mut worst = Decision::Allow;
        let mut highest = 0u8;

        // A statement is judged in the context of the transaction it is in,
        // including one opened earlier in the same batch.
        let mut in_transaction = request.in_transaction;

        for stmt in &batch.statements {
            let blast = blast::analyze(stmt, catalog);

            let risk_input = RiskInput {
                estimated_rows: blast.rows_affected.value(),
                in_transaction,
                table_rows: stmt
                    .primary_object()
                    .and_then(|o| catalog.and_then(|c| c.rows(&o.qualified()))),
            };
            let risk = risk::score(stmt, &risk_input);

            let outcome: PolicyOutcome = policy.evaluate(&MatchContext {
                statement: stmt,
                risk: &risk,
                environment: info.environment,
                agent: Some(&request.agent),
            });

            let recovery = None;
            let rollback = rollback::plan(stmt, recovery);

            worst = worst.escalate(outcome.decision.clone());
            highest = highest.max(risk.score);

            match stmt.kind {
                supasafe_parser::StatementKind::Begin => in_transaction = true,
                supasafe_parser::StatementKind::Commit
                | supasafe_parser::StatementKind::Rollback => in_transaction = false,
                _ => {}
            }

            statements.push(StatementVerdict {
                statement: stmt.clone(),
                risk,
                decision: outcome.decision,
                rule: outcome.rule,
                reasons: outcome.reasons,
                blast,
                rollback,
                wants_snapshot: outcome.snapshot,
                wants_dry_run: outcome.dry_run,
            });
        }

        Verdict {
            id: Uuid::new_v4(),
            decision: worst,
            statements,
            policy: policy.name().to_string(),
            environment: info,
            risk: highest,
        }
    }

    /// Turn a verdict into an approval request a human can answer.
    pub fn request_approval(
        &self,
        verdict: &Verdict,
        request: &Request,
        recovery_point: Option<String>,
    ) -> ApprovalRequest {
        let dominant = verdict.dominant();
        let timeout = self
            .config
            .policy(&verdict.policy)
            .map(|p| p.policy.approval_timeout_seconds)
            .unwrap_or(self.config.config.approvals.timeout_seconds);

        let approval = ApprovalRequest {
            id: verdict.id,
            created_at: Utc::now(),
            expires_at: deadline(timeout),
            agent: request.agent.clone(),
            sql: request.sql.clone(),
            description: dominant
                .map(|s| s.statement.describe())
                .unwrap_or_else(|| "run a statement".to_string()),
            reason: request.reason.clone(),
            database: verdict.environment.target.database.clone(),
            environment: verdict.environment.environment,
            policy: verdict.policy.clone(),
            affected_objects: verdict.affected_objects(),
            risk: dominant
                .map(|s| s.risk.clone())
                .unwrap_or_else(|| RiskScore {
                    score: verdict.risk,
                    level: crate::risk::RiskLevel::of(verdict.risk),
                    base: verdict.risk,
                    factors: Vec::new(),
                }),
            blast: dominant.map(|s| s.blast.clone()).unwrap_or_else(|| {
                blast::analyze(&supasafe_parser::analyze_statement("SELECT 1"), None)
            }),
            policy_reasons: dominant.map(|s| s.reasons.clone()).unwrap_or_default(),
            approvals_required: verdict.approvals_required().max(1),
            rollback: dominant
                .map(|s| s.rollback.clone())
                .unwrap_or_else(RollbackPlan::none),
            recovery_point,
            state: ApprovalState::Pending,
            approvers: Vec::new(),
        };
        self.approvals.submit(approval)
    }

    /// Record what happened.
    pub fn record(
        &self,
        verdict: &Verdict,
        request: &Request,
        outcome: Outcome,
        rows_affected: Option<u64>,
        duration_ms: Option<u64>,
        recovery_point: Option<String>,
    ) {
        let store_raw = self.audit.stores_raw_sql();
        for statement in &verdict.statements {
            let entry = AuditEntry {
                agent: request.agent.clone(),
                prompt_hash: request.prompt.as_deref().map(hash_prompt),
                sql: if store_raw {
                    statement.statement.sql.clone()
                } else {
                    statement.statement.normalized.clone()
                },
                sql_is_raw: store_raw,
                fingerprint: fingerprint(&statement.statement.normalized),
                database: verdict.environment.target.database.clone(),
                environment: Some(verdict.environment.environment),
                policy: verdict.policy.clone(),
                statement_kind: statement.statement.kind.as_str().to_string(),
                objects: statement
                    .statement
                    .objects
                    .iter()
                    .map(|o| o.qualified())
                    .collect(),
                risk: statement.risk.score,
                decision: Some(statement.decision.clone()),
                rule: statement.rule.clone(),
                reasons: statement.reasons.clone(),
                outcome: Some(outcome.clone()),
                rows_affected,
                duration_ms,
                recovery_point: recovery_point.clone(),
            };
            if let Err(e) = self.audit.append(entry) {
                // An audit failure must be loud. It must not stop the proxy
                // from enforcing policy, because a guard that fails open on a
                // full disk is worse than one that cannot write its log.
                tracing::error!(error = %e, "failed to write an audit record");
            }
        }
    }

    /// The standing instructions for agents on this connection.
    pub fn agent_context(&self, target: &ConnectionTarget) -> String {
        let info = self.config.classify(target);
        let policy = self.config.policy_for(&info);
        context::instructions(
            &info,
            policy,
            &self.config.config.context.extra_instructions,
        )
    }
}

/// A stable identifier for a statement shape.
pub fn fingerprint(normalized: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(normalized.as_bytes()))[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ApprovalSettings, ApprovalStore};
    use crate::config::Config;
    use crate::environment::Environment;

    fn guard() -> Guard {
        Guard::new(
            Config::default().compile().unwrap(),
            Arc::new(AuditLog::in_memory()),
            ApprovalStore::new(ApprovalSettings::default()),
        )
    }

    fn prod() -> ConnectionTarget {
        ConnectionTarget::new("db.abcdefghijklmnopqrst.supabase.co", 5432, "postgres")
    }

    fn local() -> ConnectionTarget {
        ConnectionTarget::new("localhost", 5432, "myapp_dev")
    }

    #[test]
    fn the_headline_case_is_blocked() {
        let g = guard();
        let v = g.evaluate(&Request::new("DROP TABLE users"), &prod());
        assert!(v.blocks_execution());
        assert_eq!(v.environment.environment, Environment::Production);
        assert_eq!(v.risk, 100);
        assert!(v.message().contains("permanently remove the table users"));
    }

    #[test]
    fn the_same_statement_runs_locally() {
        let g = guard();
        let v = g.evaluate(&Request::new("DROP TABLE users"), &local());
        assert!(!v.blocks_execution());
        assert_eq!(v.environment.environment, Environment::Local);
        // The score is a property of the statement, not the environment.
        assert_eq!(v.risk, 100);
    }

    #[test]
    fn a_batch_is_as_safe_as_its_worst_statement() {
        let g = guard();
        let v = g.evaluate(
            &Request::new("SELECT 1; DROP TABLE users; SELECT 2"),
            &prod(),
        );
        assert_eq!(v.statements.len(), 3);
        assert!(v.blocks_execution());
        assert_eq!(
            v.dominant().unwrap().statement.kind,
            supasafe_parser::StatementKind::DropTable
        );
    }

    #[test]
    fn ordinary_traffic_is_not_disturbed() {
        let g = guard();
        for sql in [
            "SELECT id, email FROM users WHERE id = $1",
            "INSERT INTO events (name) VALUES ($1)",
            "UPDATE users SET last_seen = now() WHERE id = $1",
            "DELETE FROM sessions WHERE id = $1",
            "BEGIN",
            "COMMIT",
        ] {
            let v = g.evaluate(&Request::new(sql), &prod());
            assert!(!v.blocks_execution(), "blocked ordinary traffic: {sql}");
        }
    }

    #[test]
    fn auth_schema_writes_are_refused_outright() {
        let g = guard();
        let v = g.evaluate(
            &Request::new("DELETE FROM auth.users WHERE id = $1"),
            &prod(),
        );
        assert_eq!(v.decision, Decision::Deny);
    }

    #[test]
    fn an_approval_request_carries_what_a_human_needs() {
        let g = guard();
        let request = Request::new("TRUNCATE TABLE public.orders").from_agent("claude-code");
        let v = g.evaluate(&request, &prod());
        assert!(v.needs_approval());

        let approval = g.request_approval(&v, &request, Some("snap-1".into()));
        assert_eq!(approval.agent, "claude-code");
        assert!(approval.description.contains("empty"));
        assert!(!approval.affected_objects.is_empty());
        assert_eq!(approval.recovery_point.as_deref(), Some("snap-1"));
        assert_eq!(
            approval.rollback.reversibility,
            crate::rollback::Reversibility::Irreversible
        );
        assert!(!approval.risk.factors.is_empty());
    }

    #[test]
    fn transactions_opened_in_the_batch_are_tracked() {
        let g = guard();
        let v = g.evaluate(
            &Request::new("BEGIN; DELETE FROM sessions WHERE status = 'stale'"),
            &prod(),
        );
        let delete = &v.statements[1];
        assert!(delete
            .risk
            .factors
            .iter()
            .any(|f| f.code == "in_transaction"));
    }

    #[test]
    fn the_audit_trail_records_the_decision() {
        let g = guard();
        let request = Request::new("DROP TABLE users").from_agent("claude-code");
        let v = g.evaluate(&request, &prod());
        g.record(&v, &request, Outcome::Blocked, None, None, None);
        // The in-memory log keeps no file, but the chain still advanced.
        assert!(g.audit().verify().unwrap().is_intact());
    }

    #[test]
    fn audit_records_do_not_carry_literals_by_default() {
        let g = guard();
        let request = Request::new("DELETE FROM users WHERE email = 'ada@example.com'");
        let v = g.evaluate(&request, &prod());
        let store_raw = g.audit().stores_raw_sql();
        assert!(!store_raw);
        let normalized = &v.statements[0].statement.normalized;
        assert!(!normalized.contains("ada@example.com"));
    }

    #[test]
    fn context_is_produced_for_the_connection() {
        let g = guard();
        let text = g.agent_context(&prod());
        assert!(text.contains("PRODUCTION"));
        assert!(text.contains("Never run TRUNCATE"));
    }

    #[test]
    fn fingerprints_group_the_same_shape() {
        assert_eq!(
            fingerprint(&supasafe_parser::normalize("SELECT * FROM t WHERE id = 1")),
            fingerprint(&supasafe_parser::normalize("SELECT * FROM t WHERE id = 2"))
        );
        assert_ne!(
            fingerprint(&supasafe_parser::normalize("SELECT * FROM t")),
            fingerprint(&supasafe_parser::normalize("DELETE FROM t"))
        );
    }
}
