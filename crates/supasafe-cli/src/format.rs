//! Terminal output.
//!
//! The verdict block is the thing people will read most, usually while
//! something is on fire. It leads with the decision, says what the statement
//! would do in one sentence, and only then explains itself.
//!
//! Colour is switched off when stdout is not a terminal, or when `NO_COLOR` is
//! set, so piping to a file gives clean text.

use supasafe_core::audit::AuditRecord;
use supasafe_core::environment::EnvironmentInfo;
use supasafe_core::guard::Verdict;
use supasafe_core::policy::{Decision, Policy};
use supasafe_core::risk::RiskLevel;

fn colour_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false) {
        return false;
    }
    // Without a terminal on the other end, escape codes are just noise in
    // somebody's log file.
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

fn paint(code: &str, text: &str) -> String {
    if colour_enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn red(text: &str) -> String {
    paint("31", text)
}
pub fn green(text: &str) -> String {
    paint("32", text)
}
pub fn amber(text: &str) -> String {
    paint("33", text)
}
pub fn violet(text: &str) -> String {
    paint("35", text)
}
pub fn dim(text: &str) -> String {
    paint("2", text)
}
pub fn bold(text: &str) -> String {
    paint("1", text)
}

fn risk_colour(level: RiskLevel) -> fn(&str) -> String {
    match level {
        RiskLevel::None | RiskLevel::Low => green,
        RiskLevel::Moderate | RiskLevel::High => amber,
        RiskLevel::Critical | RiskLevel::Catastrophic => red,
    }
}

fn decision_colour(decision: &Decision) -> fn(&str) -> String {
    match decision {
        Decision::Allow => green,
        Decision::Warn => amber,
        Decision::RequireApproval { .. } => violet,
        Decision::Deny => red,
    }
}

/// The block printed when the proxy starts.
pub fn banner(info: &EnvironmentInfo, policy: &str, listen: &str) {
    let env = info.environment.to_string().to_uppercase();
    let coloured = match info.environment {
        supasafe_core::Environment::Production => red(&env),
        supasafe_core::Environment::Staging => amber(&env),
        _ => green(&env),
    };

    println!();
    println!("  {} {}", bold("SupaSafe"), dim(supasafe_core::VERSION));
    println!("  {} guarding    {}", dim("│"), info.summary());
    println!("  {} environment {coloured}", dim("│"));
    println!("  {} policy      {policy}", dim("│"));
    println!("  {} agents to   postgresql://…@{listen}/…", dim("│"));

    if info.assumed {
        println!(
            "  {} {}",
            dim("│"),
            amber("no signal identified this database, so it is treated as production"),
        );
    }
}

/// The result of `supasafe analyze`.
pub fn verdict(verdict: &Verdict) {
    let paint_decision = decision_colour(&verdict.decision);
    let headline = match &verdict.decision {
        Decision::Allow => "ALLOWED",
        Decision::Warn => "ALLOWED WITH A WARNING",
        Decision::RequireApproval { .. } => "HELD FOR APPROVAL",
        Decision::Deny => "BLOCKED",
    };

    println!();
    println!(
        "  {}  {} {} policy in {}",
        paint_decision(headline),
        dim("under the"),
        verdict.policy,
        verdict.environment.environment
    );

    if verdict.environment.assumed {
        println!(
            "  {}",
            dim("(no signal identified this database, so it is treated as production)")
        );
    }

    for statement in &verdict.statements {
        let level = statement.risk.level;
        println!();
        println!(
            "  {} {}  {}",
            risk_colour(level)(&format!("risk {:>3}", statement.risk.score)),
            dim(&format!("({level})")),
            bold(&statement.statement.describe())
        );
        // Echo the statement as it was written. Normalisation exists to keep
        // literals out of the audit log, not to obscure what the person at the
        // keyboard just typed.
        println!("  {}", dim(&statement.statement.sql));

        if !statement.reasons.is_empty() {
            println!();
            for reason in &statement.reasons {
                println!("    {} {reason}", dim("·"));
            }
        }

        let blast = &statement.blast;
        println!();
        println!("    {} {}", dim("blast radius:"), blast.summary());
        if !blast.warnings.is_empty() {
            for warning in &blast.warnings {
                println!("    {} {warning}", amber("!"));
            }
        }

        println!("    {} {}", dim("rollback:"), statement.rollback.summary());
        for caveat in &statement.rollback.caveats {
            println!("    {} {caveat}", amber("!"));
        }
    }
    println!();
}

/// The list printed by `supasafe approve` with no arguments.
pub fn pending_list(pending: &[&serde_json::Value]) {
    println!();
    for request in pending {
        let id = request["id"].as_str().unwrap_or("?");
        let risk = request["risk"]["score"].as_u64().unwrap_or(0) as u8;
        let level = RiskLevel::of(risk);
        println!(
            "  {} {} {}",
            risk_colour(level)(&format!("risk {risk:>3}")),
            bold(request["agent"].as_str().unwrap_or("unknown")),
            dim(&format!(
                "wants to {} on {}",
                request["description"].as_str().unwrap_or("run a statement"),
                request["database"].as_str().unwrap_or("the database"),
            ))
        );
        println!("      {}", request["sql"].as_str().unwrap_or(""));
        println!("      {}", dim(&format!("supasafe approve {id}")));
        println!();
    }
}

/// The table printed by `supasafe audit`.
pub fn audit_table(records: &[AuditRecord]) {
    println!();
    println!(
        "  {:<20} {:<14} {:>4}  {:<17} {:<10} {}",
        bold("time"),
        bold("agent"),
        bold("risk"),
        bold("decision"),
        bold("outcome"),
        bold("statement")
    );
    for record in records {
        let level = RiskLevel::of(record.risk);
        println!(
            "  {:<20} {:<14} {:>4}  {:<17} {:<10} {}",
            record.timestamp.format("%Y-%m-%d %H:%M:%S"),
            truncate(&record.agent, 14),
            risk_colour(level)(&record.risk.to_string()),
            decision_colour(&record.decision)(record.decision.as_str()),
            record.outcome.as_str(),
            truncate(&record.sql, 60),
        );
    }
    println!();
    println!(
        "  {}",
        dim("supasafe audit --verify checks the chain has not been edited")
    );
}

/// The detail printed by `supasafe policy <name>`.
pub fn policy_detail(policy: &Policy) {
    println!();
    println!("  {}", bold(&policy.name));
    println!("  {}", policy.description);
    println!();
    println!("  default action        {}", policy.default);
    if let Some(t) = policy.warn_above {
        println!("  warn above            {t}");
    }
    if let Some(t) = policy.require_approval_above {
        println!("  approval above        {t}");
    }
    if let Some(t) = policy.deny_above {
        println!("  refuse above          {t}");
    }
    println!("  approvals required    {}", policy.approvals_required);
    if let Some(t) = policy.snapshot_above {
        println!("  snapshot above        {t}");
    }
    if let Some(t) = policy.dry_run_above {
        println!("  dry run above         {t}");
    }
    println!(
        "  approval expires in   {}s",
        policy.approval_timeout_seconds
    );
    println!(
        "  managed surfaces      {}",
        if policy.protect_managed_surfaces {
            "protected"
        } else {
            "not protected"
        }
    );
    println!(
        "  unparseable SQL       {}",
        if policy.deny_unparsed {
            "refused"
        } else {
            "allowed"
        }
    );

    if policy.rules.is_empty() {
        println!();
        println!(
            "  {}",
            dim("no rules; the default and the thresholds decide")
        );
        return;
    }

    println!();
    println!("  {} (first match wins)", bold("rules"));
    for (i, rule) in policy.rules.iter().enumerate() {
        let action = Decision::Allow; // only used for colour selection below
        let _ = action;
        println!();
        println!(
            "  {:>2}. {:<18} {}",
            i + 1,
            bold(&rule.name),
            colour_action(&rule.action)
        );
        if let Some(message) = &rule.message {
            println!("      {}", dim(message));
        }
        let m = &rule.when;
        let mut conditions = Vec::new();
        if !m.kinds.is_empty() {
            conditions.push(format!("kinds: {}", m.kinds.join(", ")));
        }
        if !m.categories.is_empty() {
            conditions.push(format!("categories: {}", m.categories.join(", ")));
        }
        if !m.objects.is_empty() {
            conditions.push(format!("objects: {}", m.objects.join(", ")));
        }
        if !m.flags.is_empty() {
            conditions.push(format!("all flags: {}", m.flags.join(", ")));
        }
        if !m.any_flags.is_empty() {
            conditions.push(format!("any flag: {}", m.any_flags.join(", ")));
        }
        if let Some(u) = m.unfiltered {
            conditions.push(format!("unfiltered: {u}"));
        }
        if let Some(r) = m.max_risk {
            conditions.push(format!("risk ≤ {r}"));
        }
        if let Some(r) = m.min_risk {
            conditions.push(format!("risk ≥ {r}"));
        }
        if conditions.is_empty() {
            conditions.push("anything not matched above".to_string());
        }
        println!("      {}", dim(&format!("when {}", conditions.join("; "))));
    }
    println!();
}

fn colour_action(action: &str) -> String {
    match action {
        "allow" => green(action),
        "warn" => amber(action),
        "require_approval" => violet(action),
        "deny" => red(action),
        other => other.to_string(),
    }
}

fn truncate(text: &str, width: usize) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= width {
        return flat;
    }
    let cut: String = flat.chars().take(width.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_keeps_the_table_aligned() {
        assert_eq!(truncate("SELECT 1", 20), "SELECT 1");
        assert_eq!(truncate("SELECT    1", 20), "SELECT 1");
        assert_eq!(truncate(&"x".repeat(80), 10).chars().count(), 10);
    }

    #[test]
    fn colour_is_off_when_not_a_terminal() {
        // Tests do not run against a terminal, so the helpers must return
        // clean text rather than escape codes.
        assert_eq!(red("boom"), "boom");
        assert!(!bold("x").contains('\x1b'));
    }
}
