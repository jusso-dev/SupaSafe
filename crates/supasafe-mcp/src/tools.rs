//! The tools SupaSafe exposes over MCP.
//!
//! Each one answers a question an agent should be asking before it writes to a
//! database it does not own:
//!
//! | tool | question |
//! |---|---|
//! | `analyze_sql` | what does this statement actually do? |
//! | `estimate_risk` | how bad is it, and why? |
//! | `preview_sql` | what will change if I run it? |
//! | `request_approval` | can a human say yes to this? |
//! | `list_policies` | what am I allowed to do here? |
//! | `create_snapshot` | can I get back if this goes wrong? |
//! | `rollback` | how do I get back? |

use serde_json::{json, Value};

use supasafe_core::audit::Outcome;
use supasafe_core::guard::Request;
use supasafe_core::snapshot::tables_to_capture;
use supasafe_core::{blast::Estimate, rollback};

use crate::{McpError, McpServer, ToolOutcome};

/// The tool catalogue, in MCP's schema format.
pub fn list() -> Value {
    json!({
        "tools": [
            {
                "name": "analyze_sql",
                "title": "Analyze SQL",
                "description":
                    "Parse a SQL statement and report what it does: statement kind, the tables \
                     and schemas it touches, whether its WHERE clause actually filters anything, \
                     and whether it would be allowed on the connected database. Call this before \
                     running anything you did not write yourself.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string", "description": "The SQL to analyse." }
                    },
                    "required": ["sql"]
                }
            },
            {
                "name": "estimate_risk",
                "title": "Estimate risk",
                "description":
                    "Score a statement from 0 to 100 and list every factor behind the score. \
                     0 is a read, 100 is irreversible loss of data or control.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string", "description": "The SQL to score." }
                    },
                    "required": ["sql"]
                }
            },
            {
                "name": "preview_sql",
                "title": "Preview SQL",
                "description":
                    "Show what would change: rows before and after, tables reached through \
                     cascading foreign keys, locks taken, and how long it is likely to run. \
                     Nothing is executed.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string", "description": "The SQL to preview." }
                    },
                    "required": ["sql"]
                }
            },
            {
                "name": "request_approval",
                "title": "Request approval",
                "description":
                    "Ask a human to approve a statement. Returns immediately with a request id; \
                     the statement is not run by this tool. Use it when you already know a \
                     statement needs approval, so the human can decide before you try to run it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string", "description": "The SQL to be approved." },
                        "reason": {
                            "type": "string",
                            "description":
                                "Why this is needed, in plain language. This is what the human \
                                 reads first."
                        }
                    },
                    "required": ["sql"]
                }
            },
            {
                "name": "list_policies",
                "title": "List policies",
                "description":
                    "Describe the policy in force on the connected database, what environment it \
                     was detected as, and which operations are refused outright.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "create_snapshot",
                "title": "Create snapshot",
                "description":
                    "Take a recovery point before a dangerous change. Returns a label to quote \
                     when restoring.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": {
                            "type": "string",
                            "description":
                                "The statement you are about to run, used to decide which tables \
                                 to capture."
                        },
                        "tables": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Tables to capture, if you want to be explicit."
                        }
                    }
                }
            },
            {
                "name": "rollback",
                "title": "Rollback guidance",
                "description":
                    "Explain how to reverse a statement, including the reverse SQL where one \
                     exists and an honest answer where none does.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string", "description": "The statement to reverse." },
                        "recovery_point": {
                            "type": "string",
                            "description": "A snapshot label taken before the statement."
                        }
                    },
                    "required": ["sql"]
                }
            }
        ]
    })
}

/// Route a tool call.
pub async fn dispatch(
    server: &McpServer,
    name: &str,
    arguments: &Value,
) -> Result<ToolOutcome, McpError> {
    match name {
        "analyze_sql" => Ok(analyze_sql(server, sql_arg(arguments)?)),
        "estimate_risk" => Ok(estimate_risk(server, sql_arg(arguments)?)),
        "preview_sql" => Ok(preview_sql(server, sql_arg(arguments)?)),
        "request_approval" => Ok(request_approval(
            server,
            sql_arg(arguments)?,
            arguments
                .get("reason")
                .and_then(|r| r.as_str())
                .map(|s| s.to_string()),
        )),
        "list_policies" => Ok(list_policies(server)),
        "create_snapshot" => Ok(create_snapshot(server, arguments).await),
        "rollback" => Ok(rollback_guidance(
            server,
            sql_arg(arguments)?,
            arguments.get("recovery_point").and_then(|r| r.as_str()),
        )),
        other => Err(McpError::ToolNotFound(other.to_string())),
    }
}

fn sql_arg(arguments: &Value) -> Result<&str, McpError> {
    arguments
        .get("sql")
        .and_then(|s| s.as_str())
        .ok_or_else(|| McpError::InvalidParams("a \"sql\" argument is required".into()))
}

fn analyze_sql(server: &McpServer, sql: &str) -> ToolOutcome {
    let request = Request {
        sql: sql.to_string(),
        agent: server.agent.clone(),
        ..Default::default()
    };
    let verdict = server.guard.evaluate(&request, &server.target);

    let statements: Vec<Value> = verdict
        .statements
        .iter()
        .map(|s| {
            json!({
                "kind": s.statement.kind.as_str(),
                "description": s.statement.describe(),
                "objects": s.statement.objects.iter().map(|o| json!({
                    "name": o.qualified(),
                    "kind": o.kind.as_str(),
                    "access": o.access.as_str(),
                    "surface": o.surface.as_str(),
                    "protected": o.is_protected(),
                })).collect::<Vec<_>>(),
                "has_where": s.statement.predicate.present,
                "where_is_tautology": s.statement.predicate.always_true,
                "selectivity": s.statement.selectivity().as_str(),
                "flags": s.statement.flags.active(),
                "parsed": s.statement.parsed,
                "notes": s.statement.notes,
                "risk": s.risk.score,
                "decision": s.decision.as_str(),
                "reasons": s.reasons,
            })
        })
        .collect();

    let text = if verdict.blocks_execution() {
        format!(
            "This would be {} on the connected database ({}). {}",
            verdict.decision,
            verdict.environment.summary(),
            verdict.message()
        )
    } else {
        format!(
            "This would be allowed on the connected database ({}). Highest risk in the batch: {}.",
            verdict.environment.summary(),
            verdict.risk
        )
    };

    ToolOutcome::ok(
        text,
        json!({
            "environment": verdict.environment.environment.as_str(),
            "policy": verdict.policy,
            "decision": verdict.decision.as_str(),
            "would_be_blocked": verdict.blocks_execution(),
            "risk": verdict.risk,
            "statements": statements,
        }),
    )
}

fn estimate_risk(server: &McpServer, sql: &str) -> ToolOutcome {
    let request = Request {
        sql: sql.to_string(),
        agent: server.agent.clone(),
        ..Default::default()
    };
    let verdict = server.guard.evaluate(&request, &server.target);

    let Some(dominant) = verdict.dominant() else {
        return ToolOutcome::ok("Nothing to score.", json!({ "risk": 0 }));
    };

    let factors: Vec<Value> = dominant
        .risk
        .factors
        .iter()
        .map(|f| {
            json!({
                "code": f.code,
                "description": f.description,
                "delta": f.delta,
                "floor": f.floor,
            })
        })
        .collect();

    ToolOutcome::ok(
        format!(
            "Risk {} ({}). {}",
            dominant.risk.score,
            dominant.risk.level,
            dominant
                .risk
                .headline()
                .map(|f| f.description.clone())
                .unwrap_or_default()
        ),
        json!({
            "risk": dominant.risk.score,
            "level": dominant.risk.level.as_str(),
            "base": dominant.risk.base,
            "factors": factors,
        }),
    )
}

fn preview_sql(server: &McpServer, sql: &str) -> ToolOutcome {
    let request = Request {
        sql: sql.to_string(),
        agent: server.agent.clone(),
        ..Default::default()
    };
    let verdict = server.guard.evaluate(&request, &server.target);

    let previews: Vec<Value> = verdict
        .statements
        .iter()
        .map(|s| {
            let b = &s.blast;
            json!({
                "statement": s.statement.describe(),
                "rows_affected": b.rows_affected.describe(),
                "tables": b.tables.iter().map(|t| json!({
                    "table": t.table,
                    "access": t.access,
                    "rows_now": t.current_rows.describe(),
                    "rows_after": t.rows_after.describe(),
                    "lock": t.lock.as_str(),
                    "indexes": t.indexes,
                    "triggers": t.triggers,
                    "rls_enabled": t.rls_enabled,
                })).collect::<Vec<_>>(),
                "cascades_into": b.cascades.iter().map(|c| json!({
                    "table": c.table,
                    "via": c.via_constraint,
                    "on_delete": c.on_delete.as_str(),
                })).collect::<Vec<_>>(),
                "heaviest_lock": b.heaviest_lock.as_str(),
                "lock_blocks": b.heaviest_lock.blocks(),
                "wal_bytes": b.wal_bytes.describe(),
                "disk_delta_bytes": b.disk_delta_bytes,
                "estimated_duration_ms": b.duration_ms.describe(),
                "warnings": b.warnings,
                "measured": !b.estimated_without_catalog,
                "rollback": {
                    "reversibility": s.rollback.reversibility.as_str(),
                    "summary": s.rollback.summary(),
                },
            })
        })
        .collect();

    let summary = verdict
        .dominant()
        .map(|s| s.blast.summary())
        .unwrap_or_else(|| "nothing".to_string());

    let caveat = verdict
        .statements
        .first()
        .map(|s| s.blast.estimated_without_catalog)
        .unwrap_or(true);

    ToolOutcome::ok(
        format!(
            "This would affect {summary}.{}",
            if caveat {
                " These are structural estimates: SupaSafe has no read-only connection to this \
                 database, so it could not measure row counts."
            } else {
                ""
            }
        ),
        json!({ "statements": previews }),
    )
}

fn request_approval(server: &McpServer, sql: &str, reason: Option<String>) -> ToolOutcome {
    let request = Request {
        sql: sql.to_string(),
        agent: server.agent.clone(),
        reason: reason.clone(),
        ..Default::default()
    };
    let verdict = server.guard.evaluate(&request, &server.target);

    if verdict.decision == supasafe_core::policy::Decision::Deny {
        // Some things do not have an approval path, and saying so plainly
        // stops an agent looping on a request nobody can grant.
        return ToolOutcome::failed(format!(
            "This statement cannot be approved: {}. There is no approval path for it under the \
             \"{}\" policy.",
            verdict.message(),
            verdict.policy
        ));
    }

    if !verdict.needs_approval() {
        return ToolOutcome::ok(
            "This statement does not need approval; you can run it.",
            json!({ "needs_approval": false, "risk": verdict.risk }),
        );
    }

    let approval = server.guard.request_approval(&verdict, &request, None);
    server
        .guard
        .record(&verdict, &request, Outcome::Analyzed, None, None, None);

    ToolOutcome::ok(
        format!(
            "Approval requested. A human has {} seconds to answer. Do not run the statement \
             until it is approved; the proxy will refuse it anyway.",
            approval.seconds_remaining(chrono::Utc::now())
        ),
        json!({
            "needs_approval": true,
            "approval_id": approval.id,
            "expires_at": approval.expires_at,
            "approvals_required": approval.approvals_required,
            "risk": approval.risk.score,
            "affected_objects": approval.affected_objects,
            "rollback": approval.rollback.summary(),
        }),
    )
}

fn list_policies(server: &McpServer) -> ToolOutcome {
    let config = server.guard.config();
    let info = config.classify(&server.target);
    let active = config.policy_for(&info);

    let policies: Vec<Value> = config
        .policies()
        .map(|p| {
            json!({
                "name": p.name(),
                "description": p.policy.description,
                "default": p.policy.default,
                "require_approval_above": p.policy.require_approval_above,
                "approvals_required": p.policy.approvals_required,
                "protects_managed_surfaces": p.policy.protect_managed_surfaces,
                "denies_unparsed": p.policy.deny_unparsed,
                "active": p.name() == active.name(),
                "rules": p.policy.rules.iter().map(|r| json!({
                    "name": r.name,
                    "action": r.action,
                    "message": r.message,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    ToolOutcome::ok(
        format!(
            "You are connected to {} and the \"{}\" policy is in force. {}",
            info.summary(),
            active.name(),
            active.policy.description
        ),
        json!({
            "environment": info.environment.as_str(),
            "environment_assumed": info.assumed,
            "active_policy": active.name(),
            "policies": policies,
            "rules_for_agents": supasafe_core::context::rules_for(info.environment),
        }),
    )
}

async fn create_snapshot(server: &McpServer, arguments: &Value) -> ToolOutcome {
    let sql = arguments
        .get("sql")
        .and_then(|s| s.as_str())
        .unwrap_or("(unspecified statement)");

    let tables: Vec<String> = match arguments.get("tables").and_then(|t| t.as_array()) {
        Some(list) => list
            .iter()
            .filter_map(|t| t.as_str().map(|s| s.to_string()))
            .collect(),
        None => tables_to_capture(&supasafe_parser::analyze_statement(sql)),
    };

    match server
        .snapshots
        .capture(&server.target.database, sql, &tables)
        .await
    {
        Ok(snapshot) => ToolOutcome::ok(
            format!(
                "Recovery point {} taken: {}",
                snapshot.label,
                snapshot.describe()
            ),
            json!({
                "label": snapshot.label,
                "kind": snapshot.kind.as_str(),
                "captured_data": snapshot.kind.has_data(),
                "taken_at": snapshot.taken_at,
                "tables": tables,
                "restore_hint": snapshot.restore_hint,
            }),
        ),
        Err(e) => ToolOutcome::failed(format!(
            "No recovery point could be taken: {e}. Treat anything you run now as irreversible."
        )),
    }
}

fn rollback_guidance(server: &McpServer, sql: &str, recovery_point: Option<&str>) -> ToolOutcome {
    let _ = server;
    let statement = supasafe_parser::analyze_statement(sql);
    let plan = rollback::plan(&statement, recovery_point);

    ToolOutcome::ok(
        format!("{} {}", plan.reversibility.describe(), plan.summary()),
        json!({
            "reversibility": plan.reversibility.as_str(),
            "reverse_sql": plan.reverse_sql,
            "steps": plan.steps,
            "caveats": plan.caveats,
        }),
    )
}

/// Used by `preview_sql` to keep the import honest when a catalogue is absent.
#[allow(dead_code)]
fn describe(estimate: Estimate) -> String {
    estimate.describe()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::server;
    use serde_json::json;

    async fn call(name: &str, arguments: Value) -> ToolOutcome {
        let s = server();
        dispatch(&s, name, &arguments).await.expect("tool runs")
    }

    #[tokio::test]
    async fn analyze_reports_the_shape_of_a_statement() {
        let out = call(
            "analyze_sql",
            json!({ "sql": "DELETE FROM users WHERE 1=1" }),
        )
        .await;
        let stmt = &out.data["statements"][0];
        assert_eq!(stmt["kind"], "delete");
        assert_eq!(stmt["has_where"], true);
        assert_eq!(stmt["where_is_tautology"], true);
        assert_eq!(stmt["selectivity"], "unbounded");
        assert_eq!(out.data["would_be_blocked"], true);
    }

    #[tokio::test]
    async fn analyze_names_the_supabase_surface() {
        let out = call("analyze_sql", json!({ "sql": "DROP TABLE auth.users" })).await;
        let object = &out.data["statements"][0]["objects"][0];
        assert_eq!(object["surface"], "supabase_auth");
        assert_eq!(object["protected"], true);
    }

    #[tokio::test]
    async fn risk_comes_with_its_factors() {
        let out = call("estimate_risk", json!({ "sql": "TRUNCATE TABLE orders" })).await;
        assert_eq!(out.data["risk"], 95);
        assert!(!out.data["factors"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn preview_admits_when_it_is_guessing() {
        let out = call("preview_sql", json!({ "sql": "DELETE FROM users" })).await;
        assert_eq!(out.data["statements"][0]["measured"], false);
        assert!(out.text.contains("structural estimates"));
    }

    #[tokio::test]
    async fn preview_names_the_lock() {
        let out = call("preview_sql", json!({ "sql": "DROP TABLE users" })).await;
        assert_eq!(
            out.data["statements"][0]["heaviest_lock"],
            "ACCESS EXCLUSIVE"
        );
    }

    #[tokio::test]
    async fn approval_is_refused_where_there_is_no_approval_path() {
        let out = call(
            "request_approval",
            json!({ "sql": "DROP TABLE auth.users" }),
        )
        .await;
        assert!(out.is_error);
        assert!(out.text.contains("cannot be approved"));
    }

    #[tokio::test]
    async fn approval_is_not_requested_for_harmless_statements() {
        let out = call("request_approval", json!({ "sql": "SELECT 1" })).await;
        assert_eq!(out.data["needs_approval"], false);
    }

    #[tokio::test]
    async fn approval_creates_a_request_a_human_can_answer() {
        let out = call(
            "request_approval",
            json!({ "sql": "TRUNCATE TABLE orders", "reason": "clearing test fixtures" }),
        )
        .await;
        assert_eq!(out.data["needs_approval"], true);
        assert!(out.data["approval_id"].is_string());
    }

    #[tokio::test]
    async fn policies_describe_what_is_in_force() {
        let out = call("list_policies", json!({})).await;
        assert_eq!(out.data["environment"], "production");
        assert_eq!(out.data["active_policy"], "production");
        assert!(!out.data["rules_for_agents"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rollback_is_honest_about_irreversible_changes() {
        let out = call("rollback", json!({ "sql": "TRUNCATE TABLE orders" })).await;
        assert_eq!(out.data["reversibility"], "irreversible");
        assert!(!out.data["caveats"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rollback_writes_the_reverse_statement_when_it_can() {
        let out = call("rollback", json!({ "sql": "CREATE TABLE t (id int)" })).await;
        assert_eq!(out.data["reversibility"], "automatic");
        assert!(out.data["reverse_sql"]
            .as_str()
            .unwrap()
            .starts_with("DROP TABLE"));
    }

    #[tokio::test]
    async fn snapshots_report_when_nothing_was_captured() {
        let out = call("create_snapshot", json!({ "sql": "DROP TABLE users" })).await;
        assert_eq!(out.data["captured_data"], false);
        assert!(out.data["restore_hint"]
            .as_str()
            .unwrap()
            .contains("point-in-time"));
    }

    #[tokio::test]
    async fn a_missing_sql_argument_is_a_clear_error() {
        let s = server();
        let err = dispatch(&s, "analyze_sql", &json!({})).await.unwrap_err();
        assert!(err.to_string().contains("sql"));
    }
}
