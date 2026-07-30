//! Context served to AI agents.
//!
//! Blocking a bad statement works. Preventing the model from writing it in the
//! first place works better, and costs nobody an approval prompt at midnight.
//!
//! The MCP server exposes this text, the CLI prints it for pasting into
//! `CLAUDE.md` or `AGENTS.md`, and the proxy can return it in an error message
//! so an agent that just got blocked learns why.
//!
//! Two rules govern what goes in here. Everything is specific: "never run
//! TRUNCATE" beats "be careful". And nothing claims a capability SupaSafe does
//! not have, because an agent that is told it is protected will take bigger
//! swings than one that knows it is on its own.

use crate::environment::{Environment, EnvironmentInfo};
use crate::policy::CompiledPolicy;

/// Build the standing instructions for an agent working against this database.
pub fn instructions(info: &EnvironmentInfo, policy: &CompiledPolicy, extra: &[String]) -> String {
    let mut out = String::new();

    out.push_str("# Database safety context (provided by SupaSafe)\n\n");

    match info.environment {
        Environment::Production => {
            out.push_str(&format!(
                "You are connected to a **PRODUCTION** database ({}). Real people's data is in \
                 here and there is no undo button.\n\n",
                info.summary()
            ));
        }
        Environment::Staging => {
            out.push_str(&format!(
                "You are connected to a **STAGING** database ({}). Breaking it costs a release, \
                 not a company.\n\n",
                info.summary()
            ));
        }
        Environment::Development | Environment::Local => {
            out.push_str(&format!(
                "You are connected to a **{}** database ({}). You have room to experiment.\n\n",
                info.environment.as_str().to_uppercase(),
                info.summary()
            ));
        }
    }

    if info.assumed {
        out.push_str(
            "SupaSafe could not identify this environment from the connection, so it is being \
             treated as production. Assume the strictest rules apply.\n\n",
        );
    }

    out.push_str("## Rules\n\n");
    for rule in rules_for(info.environment) {
        out.push_str(&format!("- {rule}\n"));
    }

    out.push_str(&format!(
        "\n## What SupaSafe will do\n\n\
         Every statement you send is parsed, scored and checked against the \"{}\" policy \
         before it reaches the database. {}\n\n",
        policy.name(),
        policy_summary(policy)
    ));

    out.push_str(
        "If a statement is held for approval, a human sees the SQL, the tables it touches, the \
         estimated number of rows, and how to undo it. Write statements that are easy to say yes \
         to: name the tables, scope them with a WHERE clause on a key, and say what you are doing \
         and why.\n\n",
    );

    out.push_str(
        "If a statement is refused, do not try to get around it. Rewriting the same operation as \
         a DO block, a function, or dynamic SQL does not make it safe and SupaSafe will refuse \
         those too. Ask the person you are working with instead.\n",
    );

    if !extra.is_empty() {
        out.push_str("\n## Project rules\n\n");
        for line in extra {
            out.push_str(&format!("- {line}\n"));
        }
    }

    out
}

/// The rules themselves, as a list, for clients that want to render them
/// their own way.
pub fn rules_for(environment: Environment) -> Vec<&'static str> {
    let mut rules = vec![
        "Never run TRUNCATE. Use DELETE with a WHERE clause so the rows can be recovered.",
        "Never run DROP SCHEMA or DROP DATABASE.",
        "Never modify the `auth`, `storage`, `vault` or `supabase_migrations` schemas. Supabase \
         owns those, and changing them breaks authentication for every user of the project.",
        "Never write DELETE or UPDATE without a WHERE clause. If you genuinely mean every row, \
         say so in words and let a human decide.",
        "A WHERE clause that is always true, such as `WHERE 1=1`, is not a WHERE clause. \
         SupaSafe evaluates the predicate, not the keyword.",
        "Never disable row level security, and never drop an RLS policy. On Supabase this \
         exposes the table to anyone holding the anon key.",
        "Never grant SUPERUSER, BYPASSRLS or REPLICATION, and never change an object's owner.",
        "Prefer additive changes. Add a column rather than changing one; add a table rather than \
         renaming one. Additive changes can be deployed and rolled back independently.",
        "Put schema changes in a migration file, so every environment gets the same change in \
         the same order. Do not apply DDL by hand.",
        "Scope every write with a primary key where you can. `WHERE id = $1` is always better \
         than `WHERE status = 'pending'`.",
        "Run a SELECT with the same WHERE clause first, and check the count, before you run the \
         DELETE or UPDATE.",
    ];

    if environment == Environment::Production {
        rules.insert(
            0,
            "Do not delete data in production unless you were explicitly asked to delete that \
             specific data.",
        );
        rules.push(
            "Wrap multi-statement work in an explicit BEGIN so it can be rolled back as a unit.",
        );
    }

    rules
}

fn policy_summary(policy: &CompiledPolicy) -> String {
    let p = &policy.policy;
    let mut parts = Vec::new();
    match p.default.as_str() {
        "deny" => parts.push(
            "Nothing runs unless a rule allows it: this is an allow-list, not a block-list."
                .to_string(),
        ),
        "allow" => parts.push("Statements run unless a rule stops them.".to_string()),
        other => parts.push(format!("The default action is {other}.")),
    }
    if let Some(t) = p.require_approval_above {
        parts.push(format!(
            "Anything scoring {t} or above needs a human to approve it."
        ));
    }
    if p.approvals_required > 1 {
        parts.push(format!(
            "Approvals need {} different people.",
            p.approvals_required
        ));
    }
    if p.protect_managed_surfaces {
        parts.push(
            "Supabase's managed schemas are refused outright, with no approval path.".to_string(),
        );
    }
    if p.deny_unparsed {
        parts.push(
            "Statements SupaSafe cannot parse into a syntax tree are refused rather than guessed \
             at."
            .to_string(),
        );
    }
    parts.join(" ")
}

/// The short version, for injecting into a system prompt or an error message
/// where a page of markdown would not fit.
pub fn brief(info: &EnvironmentInfo) -> String {
    match info.environment {
        Environment::Production => format!(
            "You are operating against PRODUCTION ({}). Never perform destructive operations. \
             Never delete data without explicit confirmation. Never truncate. Never drop \
             schemas. Never modify auth tables. Always generate migrations. Prefer additive \
             changes.",
            info.summary()
        ),
        Environment::Staging => format!(
            "You are operating against STAGING ({}). Destructive operations are recorded and \
             reviewed. Prefer additive changes and generate migrations.",
            info.summary()
        ),
        _ => format!(
            "You are operating against a {} database ({}). Destructive operations are still \
             recorded.",
            info.environment,
            info.summary()
        ),
    }
}

/// The message returned to an agent when a statement is refused.
///
/// It explains the refusal and points at the alternative, because an agent
/// that only hears "no" will try the same thing a different way.
pub fn refusal_message(
    statement_description: &str,
    reasons: &[String],
    rollback_note: Option<&str>,
) -> String {
    let mut out = format!("SupaSafe blocked this statement: it would {statement_description}.");
    for reason in reasons {
        out.push_str(&format!("\n  - {reason}"));
    }
    if let Some(note) = rollback_note {
        out.push_str(&format!("\n\n{note}"));
    }
    out.push_str(
        "\n\nDo not retry this in another form. If it is genuinely required, ask a human to \
         approve it, or write it as a reviewed migration.",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::environment::{Confidence, ConnectionTarget};

    fn info(environment: Environment, assumed: bool) -> EnvironmentInfo {
        EnvironmentInfo {
            environment,
            confidence: Confidence::Strong,
            signals: vec![],
            target: ConnectionTarget::new("db.example.com", 5432, "postgres"),
            supabase_project_ref: None,
            assumed,
            label: None,
        }
    }

    #[test]
    fn production_context_is_unambiguous() {
        let config = Config::default().compile().unwrap();
        let policy = config.policy("production").unwrap();
        let text = instructions(&info(Environment::Production, false), policy, &[]);
        assert!(text.contains("PRODUCTION"));
        assert!(text.contains("Never run TRUNCATE"));
        assert!(text.contains("auth"));
        assert!(text.contains("allow-list"));
    }

    #[test]
    fn an_assumed_environment_says_so() {
        let config = Config::default().compile().unwrap();
        let policy = config.policy("production").unwrap();
        let text = instructions(&info(Environment::Production, true), policy, &[]);
        assert!(text.contains("could not identify this environment"));
    }

    #[test]
    fn project_rules_are_appended() {
        let config = Config::default().compile().unwrap();
        let policy = config.policy("production").unwrap();
        let text = instructions(
            &info(Environment::Production, false),
            policy,
            &["Never touch the billing schema.".to_string()],
        );
        assert!(text.contains("Never touch the billing schema."));
    }

    #[test]
    fn the_brief_covers_the_required_points() {
        let text = brief(&info(Environment::Production, false));
        for phrase in [
            "PRODUCTION",
            "Never perform destructive operations",
            "Never truncate",
            "Never drop",
            "auth tables",
            "migrations",
            "additive",
        ] {
            assert!(text.contains(phrase), "missing {phrase:?} in: {text}");
        }
    }

    #[test]
    fn refusals_tell_the_agent_not_to_route_around_them() {
        let msg = refusal_message(
            "permanently remove the table users",
            &["production policy refuses irreversible operations".to_string()],
            Some("There is no snapshot to restore from."),
        );
        assert!(msg.contains("Do not retry this in another form"));
        assert!(msg.contains("permanently remove the table users"));
    }

    #[test]
    fn every_environment_produces_rules() {
        for env in [
            Environment::Local,
            Environment::Development,
            Environment::Staging,
            Environment::Production,
        ] {
            assert!(!rules_for(env).is_empty());
        }
    }
}
