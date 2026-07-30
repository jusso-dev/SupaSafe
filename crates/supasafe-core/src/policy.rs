//! The policy engine.
//!
//! A policy answers: given this statement, this score and this environment,
//! what happens?
//!
//! The model is an allow-list. A policy declares a default action, and the
//! default that ships for production is `deny`. Statements are permitted
//! because a rule says so, not because no rule happened to object. That is the
//! difference between "we blocked the dangerous things we thought of" and "we
//! allowed the safe things we chose".

use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::fmt;
use supasafe_parser::{ManagedSurface, StatementAnalysis};

use crate::environment::Environment;
use crate::risk::{RiskLevel, RiskScore};

/// What SupaSafe does with a statement.
///
/// Ordered by severity: escalation only ever moves right.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum Decision {
    /// Forward it.
    Allow,
    /// Forward it, and record that it deserved attention.
    Warn,
    /// Hold it until a human approves.
    RequireApproval { approvals: u8 },
    /// Refuse it. The statement never reaches the database.
    Deny,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Warn => "warn",
            Decision::RequireApproval { .. } => "require_approval",
            Decision::Deny => "deny",
        }
    }

    pub fn blocks_execution(&self) -> bool {
        matches!(self, Decision::Deny | Decision::RequireApproval { .. })
    }

    /// Take the more severe of two decisions.
    pub fn escalate(self, other: Decision) -> Decision {
        if other > self {
            other
        } else {
            self
        }
    }

    fn parse(s: &str, approvals: u8) -> Option<Decision> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Decision::Allow),
            "warn" => Some(Decision::Warn),
            "require_approval" | "approve" | "approval" => {
                Some(Decision::RequireApproval { approvals })
            }
            "deny" | "block" => Some(Decision::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::RequireApproval { approvals } if *approvals > 1 => {
                write!(f, "require {approvals} approvals")
            }
            other => f.write_str(other.as_str()),
        }
    }
}

/// Which statements a rule applies to. Every field that is set must match;
/// fields left empty do not constrain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Matcher {
    /// Statement kinds, e.g. `["drop_table", "truncate"]`.
    pub kinds: Vec<String>,
    /// Statement families, e.g. `["ddl", "write"]`.
    pub categories: Vec<String>,
    /// Glob patterns against `schema.object`, e.g. `["auth.*", "public.audit_*"]`.
    pub objects: Vec<String>,
    /// Schema names.
    pub schemas: Vec<String>,
    /// Managed surfaces, e.g. `["supabase_auth"]`.
    pub surfaces: Vec<String>,
    /// Every listed flag must be set.
    pub flags: Vec<String>,
    /// At least one listed flag must be set.
    pub any_flags: Vec<String>,
    /// Inclusive lower bound on the risk score.
    pub min_risk: Option<u8>,
    /// Inclusive upper bound on the risk score.
    pub max_risk: Option<u8>,
    /// Risk band, as an alternative to a number.
    pub level: Option<String>,
    /// Match writes with (false) or without (true) an effective row filter.
    pub unfiltered: Option<bool>,
    /// Only in these environments.
    pub environments: Vec<String>,
    /// Only when the statement failed to parse into a syntax tree.
    pub unparsed: Option<bool>,
    /// Glob patterns against the client's `application_name`.
    pub agents: Vec<String>,
}

/// A compiled matcher. Globs are compiled once when the policy loads so that a
/// malformed pattern is a configuration error rather than a silent
/// never-matches at request time.
#[derive(Debug, Clone)]
struct CompiledMatcher {
    objects: Vec<GlobMatcher>,
    agents: Vec<GlobMatcher>,
    raw: Matcher,
}

impl CompiledMatcher {
    fn compile(m: &Matcher) -> Result<Self, PolicyError> {
        let compile_globs = |pats: &[String]| -> Result<Vec<GlobMatcher>, PolicyError> {
            pats.iter()
                .map(|p| {
                    Glob::new(p)
                        .map(|g| g.compile_matcher())
                        .map_err(|e| PolicyError::BadGlob {
                            pattern: p.clone(),
                            reason: e.to_string(),
                        })
                })
                .collect()
        };
        Ok(Self {
            objects: compile_globs(&m.objects)?,
            agents: compile_globs(&m.agents)?,
            raw: m.clone(),
        })
    }

    fn matches(&self, ctx: &MatchContext<'_>) -> bool {
        let m = &self.raw;
        let stmt = ctx.statement;

        if !m.kinds.is_empty() && !m.kinds.iter().any(|k| k == stmt.kind.as_str()) {
            return false;
        }
        if !m.categories.is_empty() && !m.categories.iter().any(|c| c == stmt.category().as_str()) {
            return false;
        }
        if !self.objects.is_empty() {
            let hit = stmt.objects.iter().any(|o| {
                let qualified = o.qualified();
                self.objects
                    .iter()
                    .any(|g| g.is_match(&qualified) || g.is_match(&o.name))
            });
            if !hit {
                return false;
            }
        }
        if !m.schemas.is_empty() {
            let hit = stmt.objects.iter().any(|o| {
                let schema = o.schema.clone().unwrap_or_else(|| "public".into());
                m.schemas.iter().any(|s| s.eq_ignore_ascii_case(&schema))
            });
            if !hit {
                return false;
            }
        }
        if !m.surfaces.is_empty() {
            let hit = stmt
                .objects
                .iter()
                .any(|o| m.surfaces.iter().any(|s| s == o.surface.as_str()));
            if !hit {
                return false;
            }
        }
        if !m.flags.is_empty() && !m.flags.iter().all(|f| stmt.flags.get(f)) {
            return false;
        }
        if !m.any_flags.is_empty() && !m.any_flags.iter().any(|f| stmt.flags.get(f)) {
            return false;
        }
        if let Some(min) = m.min_risk {
            if ctx.risk.score < min {
                return false;
            }
        }
        if let Some(max) = m.max_risk {
            if ctx.risk.score > max {
                return false;
            }
        }
        if let Some(level) = &m.level {
            match RiskLevel::parse(level) {
                Some(l) if ctx.risk.level != l => return false,
                None => return false,
                _ => {}
            }
        }
        if let Some(unfiltered) = m.unfiltered {
            if stmt.predicate.is_unfiltered() != unfiltered {
                return false;
            }
        }
        if let Some(unparsed) = m.unparsed {
            if stmt.parsed == unparsed {
                return false;
            }
        }
        if !m.environments.is_empty() {
            let env = ctx.environment.as_str();
            if !m.environments.iter().any(|e| e == env) {
                return false;
            }
        }
        if !self.agents.is_empty() {
            let agent = ctx.agent.unwrap_or("");
            if !self.agents.iter().any(|g| g.is_match(agent)) {
                return false;
            }
        }
        true
    }
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// A short name that appears in the audit log and in the block message.
    pub name: String,
    /// What to do when the rule matches.
    pub action: String,
    /// How many approvals, when the action requires them.
    #[serde(default)]
    pub approvals: Option<u8>,
    /// Explanation shown to the human and to the agent.
    #[serde(default)]
    pub message: Option<String>,
    /// Conditions.
    #[serde(default, rename = "when")]
    pub when: Matcher,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rule: Rule,
    matcher: CompiledMatcher,
    decision: Decision,
}

/// Thresholds applied when no rule matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Human name, filled in from the table key when loaded.
    #[serde(skip)]
    pub name: String,
    /// Inherit every setting from another policy, and put this policy's rules
    /// in front of that policy's rules.
    ///
    /// A policy that reuses a built-in name (`production`, `staging`,
    /// `development`, `regulated`) extends it automatically, so adding one rule
    /// adds one rule rather than silently discarding the twelve that were
    /// already there.
    pub extends: Option<String>,
    /// A sentence describing the intent of this policy.
    pub description: String,
    /// What happens to a statement no rule matched and no threshold caught.
    pub default: String,
    /// Score at or above which a statement is only warned about.
    pub warn_above: Option<u8>,
    /// Score at or above which a statement needs human approval.
    pub require_approval_above: Option<u8>,
    /// Score at or above which a statement is refused outright.
    pub deny_above: Option<u8>,
    /// How many distinct approvers are needed.
    pub approvals_required: u8,
    /// Score at or above which SupaSafe takes a snapshot before executing.
    pub snapshot_above: Option<u8>,
    /// Score at or above which SupaSafe runs the statement through EXPLAIN
    /// before letting it execute.
    pub dry_run_above: Option<u8>,
    /// Refuse statements that could not be parsed into a syntax tree.
    pub deny_unparsed: bool,
    /// Refuse any statement that would modify a protected managed surface.
    pub protect_managed_surfaces: bool,
    /// How long an approval request stays open, in seconds.
    pub approval_timeout_seconds: u64,
    /// Ordered rules. The first match wins.
    pub rules: Vec<Rule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            name: String::new(),
            extends: None,
            description: String::new(),
            default: "deny".to_string(),
            warn_above: None,
            require_approval_above: None,
            deny_above: None,
            approvals_required: 1,
            snapshot_above: None,
            dry_run_above: None,
            deny_unparsed: true,
            protect_managed_surfaces: true,
            approval_timeout_seconds: 300,
            rules: Vec::new(),
        }
    }
}

/// Errors raised while loading a policy.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid glob pattern {pattern:?}: {reason}")]
    BadGlob { pattern: String, reason: String },
    #[error("rule {rule:?} has unknown action {action:?}; expected allow, warn, require_approval or deny")]
    BadAction { rule: String, action: String },
    #[error("policy {policy:?} has unknown default action {action:?}")]
    BadDefault { policy: String, action: String },
    #[error("no policy named {0:?} is defined")]
    Unknown(String),
}

/// A policy with its globs compiled and its actions validated.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub policy: Policy,
    rules: Vec<CompiledRule>,
    default: Decision,
}

impl CompiledPolicy {
    pub fn compile(policy: Policy) -> Result<Self, PolicyError> {
        let default =
            Decision::parse(&policy.default, policy.approvals_required).ok_or_else(|| {
                PolicyError::BadDefault {
                    policy: policy.name.clone(),
                    action: policy.default.clone(),
                }
            })?;

        let rules = policy
            .rules
            .iter()
            .map(|r| {
                let approvals = r.approvals.unwrap_or(policy.approvals_required).max(1);
                let decision = Decision::parse(&r.action, approvals).ok_or_else(|| {
                    PolicyError::BadAction {
                        rule: r.name.clone(),
                        action: r.action.clone(),
                    }
                })?;
                Ok(CompiledRule {
                    matcher: CompiledMatcher::compile(&r.when)?,
                    rule: r.clone(),
                    decision,
                })
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;

        Ok(Self {
            policy,
            rules,
            default,
        })
    }

    pub fn name(&self) -> &str {
        &self.policy.name
    }
}

/// Everything a rule can be evaluated against.
#[derive(Debug, Clone, Copy)]
pub struct MatchContext<'a> {
    pub statement: &'a StatementAnalysis,
    pub risk: &'a RiskScore,
    pub environment: Environment,
    pub agent: Option<&'a str>,
}

/// Why SupaSafe decided what it decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutcome {
    pub decision: Decision,
    /// The rule that decided, when one did.
    pub rule: Option<String>,
    /// Sentences explaining the decision, ready to show a human or return to
    /// an agent.
    pub reasons: Vec<String>,
    /// Take a snapshot before executing.
    pub snapshot: bool,
    /// Run the statement through EXPLAIN before executing.
    pub dry_run: bool,
}

impl CompiledPolicy {
    /// Decide what happens to one statement.
    pub fn evaluate(&self, ctx: &MatchContext<'_>) -> PolicyOutcome {
        let p = &self.policy;
        let mut reasons = Vec::new();

        // Non-negotiable guards run before the rules. An operator who wants
        // them off turns them off in configuration, not by writing a rule that
        // happens to match first.
        if p.protect_managed_surfaces {
            let protected = ctx.statement.protected_objects();
            if let Some(obj) = protected.first() {
                if let Some(why) = obj.surface.why_it_matters() {
                    return PolicyOutcome {
                        decision: Decision::Deny,
                        rule: Some("protect_managed_surfaces".to_string()),
                        reasons: vec![format!(
                            "{} would modify {}, which SupaSafe protects because {why}",
                            ctx.statement.kind.label(),
                            obj.as_written()
                        )],
                        snapshot: false,
                        dry_run: false,
                    };
                }
            }
        }

        if p.deny_unparsed && !ctx.statement.parsed {
            return PolicyOutcome {
                decision: Decision::Deny,
                rule: Some("deny_unparsed".to_string()),
                reasons: vec![
                    "this statement could not be parsed into a syntax tree, and this policy does \
                     not allow statements SupaSafe cannot fully verify"
                        .to_string(),
                ],
                snapshot: false,
                dry_run: false,
            };
        }

        // Ordered rules: first match wins.
        for compiled in &self.rules {
            if compiled.matcher.matches(ctx) {
                let mut reasons = Vec::new();
                if let Some(msg) = &compiled.rule.message {
                    reasons.push(msg.clone());
                } else {
                    reasons.push(format!(
                        "policy rule \"{}\" applies to this statement",
                        compiled.rule.name
                    ));
                }
                let decision = compiled.decision.clone();
                return PolicyOutcome {
                    snapshot: self.wants_snapshot(ctx, &decision),
                    dry_run: self.wants_dry_run(ctx),
                    decision,
                    rule: Some(compiled.rule.name.clone()),
                    reasons,
                };
            }
        }

        // No rule matched: the default, escalated by the score thresholds.
        let mut decision = self.default.clone();
        let score = ctx.risk.score;

        if let Some(t) = p.warn_above {
            if score >= t {
                decision = decision.escalate(Decision::Warn);
            }
        }
        if let Some(t) = p.require_approval_above {
            if score >= t {
                decision = decision.escalate(Decision::RequireApproval {
                    approvals: p.approvals_required.max(1),
                });
                reasons.push(format!(
                    "risk {score} is at or above this policy's approval threshold of {t}"
                ));
            }
        }
        if let Some(t) = p.deny_above {
            if score >= t {
                decision = decision.escalate(Decision::Deny);
                reasons.push(format!(
                    "risk {score} is at or above this policy's refusal threshold of {t}"
                ));
            }
        }

        if reasons.is_empty() {
            reasons.push(match decision {
                Decision::Allow => format!(
                    "policy \"{}\" allows this by default and nothing escalated it",
                    p.name
                ),
                _ => format!(
                    "policy \"{}\" defaults to {} for statements no rule allows",
                    p.name, decision
                ),
            });
        }

        PolicyOutcome {
            snapshot: self.wants_snapshot(ctx, &decision),
            dry_run: self.wants_dry_run(ctx),
            decision,
            rule: None,
            reasons,
        }
    }

    fn wants_snapshot(&self, ctx: &MatchContext<'_>, decision: &Decision) -> bool {
        if *decision == Decision::Deny {
            return false;
        }
        match self.policy.snapshot_above {
            Some(t) => ctx.risk.score >= t,
            None => false,
        }
    }

    fn wants_dry_run(&self, ctx: &MatchContext<'_>) -> bool {
        match self.policy.dry_run_above {
            Some(t) => ctx.risk.score >= t,
            None => false,
        }
    }
}

/// Whether a surface should be protected by default, used when generating the
/// starter configuration.
pub fn default_protected_surfaces() -> Vec<ManagedSurface> {
    vec![
        ManagedSurface::SupabaseAuth,
        ManagedSurface::SupabaseStorage,
        ManagedSurface::SupabaseVault,
        ManagedSurface::SupabaseMigrations,
        ManagedSurface::SystemCatalog,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::{score, RiskInput};
    use supasafe_parser::analyze_statement;

    fn policy(toml_src: &str) -> CompiledPolicy {
        let mut p: Policy = toml::from_str(toml_src).expect("policy parses");
        p.name = "test".to_string();
        CompiledPolicy::compile(p).expect("policy compiles")
    }

    fn decide(p: &CompiledPolicy, sql: &str, env: Environment) -> PolicyOutcome {
        let stmt = analyze_statement(sql);
        let risk = score(&stmt, &RiskInput::default());
        p.evaluate(&MatchContext {
            statement: &stmt,
            risk: &risk,
            environment: env,
            agent: None,
        })
    }

    #[test]
    fn default_deny_blocks_anything_unmatched() {
        let p = policy(r#"default = "deny""#);
        assert_eq!(
            decide(&p, "SELECT 1", Environment::Production).decision,
            Decision::Deny
        );
    }

    #[test]
    fn an_allow_rule_lets_reads_through() {
        let p = policy(
            r#"
            default = "deny"
            [[rules]]
            name = "allow-reads"
            action = "allow"
            when = { categories = ["read"] }
            "#,
        );
        assert_eq!(
            decide(&p, "SELECT 1", Environment::Production).decision,
            Decision::Allow
        );
        assert_eq!(
            decide(&p, "DROP TABLE t", Environment::Production).decision,
            Decision::Deny
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let p = policy(
            r#"
            default = "allow"
            [[rules]]
            name = "first"
            action = "warn"
            when = { kinds = ["delete"] }
            [[rules]]
            name = "second"
            action = "deny"
            when = { kinds = ["delete"] }
            "#,
        );
        let out = decide(&p, "DELETE FROM t WHERE id=1", Environment::Production);
        assert_eq!(out.decision, Decision::Warn);
        assert_eq!(out.rule.as_deref(), Some("first"));
    }

    #[test]
    fn thresholds_escalate_the_default() {
        let p = policy(
            r#"
            default = "allow"
            require_approval_above = 50
            deny_above = 95
            protect_managed_surfaces = false
            "#,
        );
        assert_eq!(
            decide(&p, "SELECT 1", Environment::Production).decision,
            Decision::Allow
        );
        assert_eq!(
            decide(
                &p,
                "DELETE FROM t WHERE status='x'",
                Environment::Production
            )
            .decision,
            Decision::RequireApproval { approvals: 1 }
        );
        assert_eq!(
            decide(&p, "DROP TABLE t", Environment::Production).decision,
            Decision::Deny
        );
    }

    #[test]
    fn two_person_approval_is_configurable() {
        let p = policy(
            r#"
            default = "allow"
            require_approval_above = 10
            approvals_required = 2
            protect_managed_surfaces = false
            "#,
        );
        assert_eq!(
            decide(&p, "INSERT INTO t VALUES (1)", Environment::Production).decision,
            Decision::RequireApproval { approvals: 2 }
        );
    }

    #[test]
    fn object_globs_match_schema_qualified_names() {
        let p = policy(
            r#"
            default = "allow"
            protect_managed_surfaces = false
            [[rules]]
            name = "protect-audit"
            action = "deny"
            when = { objects = ["public.audit_*"] }
            "#,
        );
        assert_eq!(
            decide(
                &p,
                "DELETE FROM audit_log WHERE id=1",
                Environment::Production
            )
            .decision,
            Decision::Deny
        );
        assert_eq!(
            decide(&p, "DELETE FROM orders WHERE id=1", Environment::Production).decision,
            Decision::Allow
        );
    }

    #[test]
    fn managed_surfaces_are_protected_before_rules_run() {
        let p = policy(
            r#"
            default = "allow"
            [[rules]]
            name = "allow-everything"
            action = "allow"
            "#,
        );
        // Even a blanket allow rule does not open the auth schema.
        assert_eq!(
            decide(&p, "DROP TABLE auth.users", Environment::Production).decision,
            Decision::Deny
        );
    }

    #[test]
    fn managed_surface_protection_can_be_turned_off_explicitly() {
        let p = policy(
            r#"
            default = "allow"
            protect_managed_surfaces = false
            deny_unparsed = false
            "#,
        );
        assert_eq!(
            decide(
                &p,
                "DELETE FROM auth.users WHERE id=1",
                Environment::Production
            )
            .decision,
            Decision::Allow
        );
    }

    #[test]
    fn unparsed_statements_are_denied_by_default() {
        let p = policy(r#"default = "allow""#);
        let out = decide(&p, "DO $$ BEGIN PERFORM 1; END $$", Environment::Production);
        assert_eq!(out.decision, Decision::Deny);
        assert_eq!(out.rule.as_deref(), Some("deny_unparsed"));
    }

    #[test]
    fn environment_scoped_rules_only_fire_in_that_environment() {
        let p = policy(
            r#"
            default = "allow"
            protect_managed_surfaces = false
            [[rules]]
            name = "no-ddl-in-prod"
            action = "deny"
            when = { categories = ["ddl"], environments = ["production"] }
            "#,
        );
        assert_eq!(
            decide(&p, "CREATE TABLE t (id int)", Environment::Production).decision,
            Decision::Deny
        );
        assert_eq!(
            decide(&p, "CREATE TABLE t (id int)", Environment::Local).decision,
            Decision::Allow
        );
    }

    #[test]
    fn flag_matchers_work() {
        let p = policy(
            r#"
            default = "allow"
            protect_managed_surfaces = false
            [[rules]]
            name = "no-cascade"
            action = "deny"
            when = { flags = ["cascade"] }
            "#,
        );
        assert_eq!(
            decide(&p, "DROP TABLE t CASCADE", Environment::Local).decision,
            Decision::Deny
        );
        assert_eq!(
            decide(&p, "DROP TABLE t", Environment::Local).decision,
            Decision::Allow
        );
    }

    #[test]
    fn unfiltered_writes_can_be_singled_out() {
        let p = policy(
            r#"
            default = "allow"
            protect_managed_surfaces = false
            [[rules]]
            name = "no-unfiltered-writes"
            action = "deny"
            when = { kinds = ["update", "delete"], unfiltered = true }
            "#,
        );
        assert_eq!(
            decide(&p, "DELETE FROM t", Environment::Local).decision,
            Decision::Deny
        );
        assert_eq!(
            decide(&p, "DELETE FROM t WHERE id = 1", Environment::Local).decision,
            Decision::Allow
        );
    }

    #[test]
    fn bad_globs_fail_at_load_time_not_at_request_time() {
        let mut p = Policy {
            name: "bad".into(),
            ..Default::default()
        };
        p.rules.push(Rule {
            name: "broken".into(),
            action: "deny".into(),
            approvals: None,
            message: None,
            when: Matcher {
                objects: vec!["[".to_string()],
                ..Default::default()
            },
        });
        assert!(CompiledPolicy::compile(p).is_err());
    }

    #[test]
    fn bad_actions_fail_at_load_time() {
        let mut p = Policy {
            name: "bad".into(),
            ..Default::default()
        };
        p.rules.push(Rule {
            name: "broken".into(),
            action: "maybe".into(),
            approvals: None,
            message: None,
            when: Matcher::default(),
        });
        assert!(CompiledPolicy::compile(p).is_err());
    }

    #[test]
    fn decisions_order_by_severity() {
        assert!(Decision::Allow < Decision::Warn);
        assert!(Decision::Warn < Decision::RequireApproval { approvals: 1 });
        assert!(Decision::RequireApproval { approvals: 9 } < Decision::Deny);
        assert_eq!(Decision::Allow.escalate(Decision::Deny), Decision::Deny);
        assert_eq!(Decision::Deny.escalate(Decision::Allow), Decision::Deny);
    }
}
