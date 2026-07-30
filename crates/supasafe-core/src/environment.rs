//! Environment detection.
//!
//! Every policy decision starts with one question: *is this production?*
//!
//! Getting that wrong in the permissive direction is how the incident happens.
//! An agent believes it is on a scratch database, the connection string
//! actually points at the live project, and `DROP TABLE` runs unchallenged. So
//! detection here is deliberately biased: several independent signals are
//! collected, the most severe classification wins ties, and an environment
//! that cannot be identified is treated as production by default.

use serde::{Deserialize, Serialize};
use std::fmt;

/// How much a database deserves to be protected.
///
/// Ordered from least to most severe so that `max()` picks the safer answer
/// when two signals disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// A database on the developer's own machine.
    Local,
    /// A shared development database. Losing it costs an afternoon.
    Development,
    /// Pre-production. Losing it costs a release.
    Staging,
    /// Production. Losing it costs the company.
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Development => "development",
            Environment::Staging => "staging",
            Environment::Production => "production",
        }
    }

    pub fn parse(s: &str) -> Option<Environment> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" => Some(Environment::Local),
            "dev" | "development" => Some(Environment::Development),
            "stage" | "staging" | "preview" | "test" | "qa" => Some(Environment::Staging),
            "prod" | "production" | "live" => Some(Environment::Production),
            _ => None,
        }
    }

    /// The default policy name for this environment.
    pub fn default_policy(&self) -> &'static str {
        match self {
            Environment::Local => "development",
            Environment::Development => "development",
            Environment::Staging => "staging",
            Environment::Production => "production",
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How sure SupaSafe is about a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// A weak hint, such as a database name containing "dev".
    Weak,
    /// A solid indicator, such as a hostname that resolves to a loopback
    /// address.
    Strong,
    /// Something the operator stated explicitly.
    Certain,
}

/// One piece of evidence about which environment a connection points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub source: String,
    pub detail: String,
    pub suggests: Environment,
    pub confidence: Confidence,
}

impl Signal {
    fn new(
        source: &str,
        detail: impl Into<String>,
        suggests: Environment,
        confidence: Confidence,
    ) -> Self {
        Self {
            source: source.to_string(),
            detail: detail.into(),
            suggests,
            confidence,
        }
    }
}

/// The database a client is connecting to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionTarget {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    /// The `application_name` the client sent, which is how SupaSafe learns
    /// which agent is on the other end.
    pub application_name: Option<String>,
}

impl ConnectionTarget {
    pub fn new(host: impl Into<String>, port: u16, database: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            database: database.into(),
            user: String::new(),
            application_name: None,
        }
    }

    /// Parse the pieces SupaSafe needs out of a libpq-style URL.
    ///
    /// Deliberately does not retain the password.
    pub fn from_url(url: &str) -> Option<ConnectionTarget> {
        let rest = url
            .strip_prefix("postgresql://")
            .or_else(|| url.strip_prefix("postgres://"))?;
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, p),
            None => (rest, ""),
        };
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let user = userinfo
            .map(|u| u.split(':').next().unwrap_or("").to_string())
            .unwrap_or_default();
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(5432)),
            None => (hostport.to_string(), 5432),
        };
        let database = path.split('?').next().unwrap_or("").to_string();
        Some(ConnectionTarget {
            host,
            port,
            database,
            user,
            application_name: None,
        })
    }

    /// The Supabase project reference, when this target is a Supabase
    /// database.
    ///
    /// Direct connections look like `db.abcdefghijklm.supabase.co`. Pooled
    /// connections put the reference in the username instead, as
    /// `postgres.abcdefghijklm`.
    pub fn supabase_project_ref(&self) -> Option<String> {
        let host = self.host.to_ascii_lowercase();
        if host.ends_with(".supabase.co") || host.ends_with(".supabase.com") {
            if let Some(rest) = host.strip_prefix("db.") {
                if let Some(reference) = rest.split('.').next() {
                    if is_project_ref(reference) {
                        return Some(reference.to_string());
                    }
                }
            }
            // Pooler: the reference travels in the user name.
            if let Some((_, reference)) = self.user.split_once('.') {
                if is_project_ref(reference) {
                    return Some(reference.to_string());
                }
            }
        }
        None
    }

    pub fn is_supabase(&self) -> bool {
        let host = self.host.to_ascii_lowercase();
        host.ends_with(".supabase.co")
            || host.ends_with(".supabase.com")
            || host.ends_with(".supabase.net")
    }
}

/// Supabase project references are 20 lowercase letters. Checking the shape
/// avoids mistaking `db.staging.supabase.co` for a reference.
fn is_project_ref(s: &str) -> bool {
    s.len() >= 16 && s.len() <= 24 && s.chars().all(|c| c.is_ascii_lowercase())
}

/// The conclusion, with the reasoning kept alongside it so a human can audit
/// the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub environment: Environment,
    pub confidence: Confidence,
    pub signals: Vec<Signal>,
    pub target: ConnectionTarget,
    pub supabase_project_ref: Option<String>,
    /// True when nothing identified the environment and SupaSafe fell back to
    /// treating it as production.
    pub assumed: bool,
    /// A label the operator attached in configuration.
    pub label: Option<String>,
}

impl EnvironmentInfo {
    pub fn is_production(&self) -> bool {
        self.environment == Environment::Production
    }

    /// A single sentence for the CLI banner and the approval card.
    pub fn summary(&self) -> String {
        let where_ = if self.target.host.is_empty() {
            self.target.database.clone()
        } else {
            format!("{}/{}", self.target.host, self.target.database)
        };
        if self.assumed {
            format!(
                "{} (assumed, no signal identified {where_})",
                self.environment
            )
        } else {
            format!("{} ({where_})", self.environment)
        }
    }
}

/// Substrings in a database or host name that indicate a non-production
/// environment. Checked against name components, not as free text, so
/// `production_dev_notes` does not read as development.
const DEV_TOKENS: &[&str] = &["dev", "development", "local", "sandbox", "scratch", "tmp"];
const STAGING_TOKENS: &[&str] = &[
    "staging", "stage", "stg", "preview", "qa", "uat", "test", "testing", "sit",
];
const PROD_TOKENS: &[&str] = &["prod", "production", "live", "main", "primary"];

/// Split a name into components on the separators people actually use.
fn tokens(name: &str) -> Vec<String> {
    name.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn match_tokens(name: &str, needles: &[&str]) -> Option<String> {
    tokens(name)
        .into_iter()
        .find(|t| needles.contains(&t.as_str()))
}

/// Everything the detector is allowed to look at. Passing it in rather than
/// reading the process environment directly keeps detection testable and keeps
/// the proxy from being surprised by an unrelated variable.
#[derive(Debug, Clone, Default)]
pub struct DetectionInputs {
    pub target: ConnectionTarget,
    /// Environment variables, typically a filtered view of the process's own.
    pub env_vars: Vec<(String, String)>,
    /// An explicit classification from configuration. Always wins.
    pub configured: Option<Environment>,
    /// A human-facing label from configuration, such as "acme-prod".
    pub label: Option<String>,
    /// Project references the operator has declared to be production.
    pub production_project_refs: Vec<String>,
}

impl DetectionInputs {
    /// Read the environment variables SupaSafe knows how to interpret.
    pub fn from_process_env(target: ConnectionTarget) -> Self {
        const KEYS: &[&str] = &[
            "SUPASAFE_ENV",
            "APP_ENV",
            "NODE_ENV",
            "RAILS_ENV",
            "DJANGO_ENV",
            "ENVIRONMENT",
            "VERCEL_ENV",
            "RAILWAY_ENVIRONMENT",
            "FLY_APP_NAME",
            "DENO_DEPLOYMENT_ID",
            "CI",
        ];
        let env_vars = KEYS
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
            .collect();
        Self {
            target,
            env_vars,
            ..Default::default()
        }
    }
}

/// Work out which environment a connection points at.
pub fn detect(inputs: &DetectionInputs) -> EnvironmentInfo {
    let mut signals = Vec::new();
    let target = &inputs.target;

    // 1. An explicit configuration entry ends the discussion.
    if let Some(env) = inputs.configured {
        signals.push(Signal::new(
            "config",
            "environment declared in supasafe.toml",
            env,
            Confidence::Certain,
        ));
    }

    // 2. Supabase project reference.
    let project_ref = target.supabase_project_ref();
    if let Some(reference) = &project_ref {
        if inputs
            .production_project_refs
            .iter()
            .any(|r| r.eq_ignore_ascii_case(reference))
        {
            signals.push(Signal::new(
                "supabase",
                format!("project {reference} is listed as production"),
                Environment::Production,
                Confidence::Certain,
            ));
        } else {
            // A hosted Supabase project is a real, remote, billed database.
            // It is not somebody's laptop.
            signals.push(Signal::new(
                "supabase",
                format!("hosted Supabase project {reference}"),
                Environment::Production,
                Confidence::Strong,
            ));
        }
    }

    // 3. Loopback and container-local hosts.
    let host = target.host.to_ascii_lowercase();
    if is_local_host(&host) {
        signals.push(Signal::new(
            "host",
            format!("{host} is a local address"),
            Environment::Local,
            Confidence::Strong,
        ));
    }

    // 4. Names.
    if let Some(t) = match_tokens(&host, PROD_TOKENS) {
        signals.push(Signal::new(
            "host",
            format!("host name contains \"{t}\""),
            Environment::Production,
            Confidence::Strong,
        ));
    } else if let Some(t) = match_tokens(&host, STAGING_TOKENS) {
        signals.push(Signal::new(
            "host",
            format!("host name contains \"{t}\""),
            Environment::Staging,
            Confidence::Strong,
        ));
    } else if let Some(t) = match_tokens(&host, DEV_TOKENS) {
        signals.push(Signal::new(
            "host",
            format!("host name contains \"{t}\""),
            Environment::Development,
            Confidence::Weak,
        ));
    }

    let db = target.database.to_ascii_lowercase();
    if let Some(t) = match_tokens(&db, PROD_TOKENS) {
        signals.push(Signal::new(
            "database",
            format!("database name contains \"{t}\""),
            Environment::Production,
            Confidence::Weak,
        ));
    } else if let Some(t) = match_tokens(&db, STAGING_TOKENS) {
        signals.push(Signal::new(
            "database",
            format!("database name contains \"{t}\""),
            Environment::Staging,
            Confidence::Weak,
        ));
    } else if let Some(t) = match_tokens(&db, DEV_TOKENS) {
        signals.push(Signal::new(
            "database",
            format!("database name contains \"{t}\""),
            Environment::Development,
            Confidence::Weak,
        ));
    }

    // 5. Environment variables.
    for (key, value) in &inputs.env_vars {
        if key == "SUPASAFE_ENV" {
            if let Some(env) = Environment::parse(value) {
                signals.push(Signal::new(
                    "env",
                    format!("SUPASAFE_ENV={value}"),
                    env,
                    Confidence::Certain,
                ));
            }
            continue;
        }
        if key == "CI" {
            continue;
        }
        if let Some(env) = Environment::parse(value) {
            signals.push(Signal::new(
                "env",
                format!("{key}={value}"),
                env,
                Confidence::Weak,
            ));
        }
    }

    // Resolve. The highest confidence tier wins; within a tier, the most
    // severe environment wins, because being wrong in that direction only
    // costs an approval prompt.
    let best_confidence = signals.iter().map(|s| s.confidence).max();
    match best_confidence {
        Some(confidence) => {
            let environment = signals
                .iter()
                .filter(|s| s.confidence == confidence)
                .map(|s| s.suggests)
                .max()
                .unwrap_or(Environment::Production);
            EnvironmentInfo {
                environment,
                confidence,
                signals,
                target: target.clone(),
                supabase_project_ref: project_ref,
                assumed: false,
                label: inputs.label.clone(),
            }
        }
        None => EnvironmentInfo {
            // Nothing identified it. An unidentified database is treated as
            // production: the cost of a wrong guess is not symmetric.
            environment: Environment::Production,
            confidence: Confidence::Weak,
            signals: vec![Signal::new(
                "default",
                "no signal identified this database, so it is treated as production",
                Environment::Production,
                Confidence::Weak,
            )],
            target: target.clone(),
            supabase_project_ref: project_ref,
            assumed: true,
            label: inputs.label.clone(),
        },
    }
}

fn is_local_host(host: &str) -> bool {
    host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host == "0.0.0.0"
        || host.starts_with("127.")
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host == "host.docker.internal"
        // A Unix socket directory.
        || host.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(host: &str, db: &str) -> DetectionInputs {
        DetectionInputs {
            target: ConnectionTarget::new(host, 5432, db),
            ..Default::default()
        }
    }

    #[test]
    fn localhost_is_local() {
        let info = detect(&inputs("localhost", "myapp"));
        assert_eq!(info.environment, Environment::Local);
        assert!(!info.assumed);
    }

    #[test]
    fn unknown_databases_are_treated_as_production() {
        let info = detect(&inputs("db.internal.example", "app"));
        assert_eq!(info.environment, Environment::Production);
        assert!(info.assumed);
    }

    #[test]
    fn hosted_supabase_is_production_by_default() {
        let info = detect(&inputs("db.abcdefghijklmnopqrst.supabase.co", "postgres"));
        assert_eq!(info.environment, Environment::Production);
        assert_eq!(
            info.supabase_project_ref.as_deref(),
            Some("abcdefghijklmnopqrst")
        );
    }

    #[test]
    fn pooled_supabase_connections_expose_the_project_ref() {
        let mut t = ConnectionTarget::new("aws-0-us-east-1.pooler.supabase.com", 6543, "postgres");
        t.user = "postgres.abcdefghijklmnopqrst".to_string();
        let info = detect(&DetectionInputs {
            target: t,
            ..Default::default()
        });
        assert_eq!(
            info.supabase_project_ref.as_deref(),
            Some("abcdefghijklmnopqrst")
        );
        assert_eq!(info.environment, Environment::Production);
    }

    #[test]
    fn staging_host_names_are_recognised() {
        let info = detect(&inputs("staging-db.example.com", "app"));
        assert_eq!(info.environment, Environment::Staging);
    }

    #[test]
    fn production_host_names_are_recognised() {
        let info = detect(&inputs("prod-db.example.com", "app"));
        assert_eq!(info.environment, Environment::Production);
    }

    #[test]
    fn config_overrides_everything() {
        let mut i = inputs("db.abcdefghijklmnopqrst.supabase.co", "postgres");
        i.configured = Some(Environment::Development);
        assert_eq!(detect(&i).environment, Environment::Development);
    }

    #[test]
    fn supasafe_env_var_is_authoritative() {
        let mut i = inputs("some-host", "app");
        i.env_vars = vec![("SUPASAFE_ENV".into(), "staging".into())];
        assert_eq!(detect(&i).environment, Environment::Staging);
    }

    #[test]
    fn severity_wins_ties_within_a_confidence_tier() {
        // Host says staging (strong), and nothing else is stronger.
        let mut i = inputs("staging-db.example.com", "app");
        i.env_vars = vec![("NODE_ENV".into(), "development".into())];
        // Weak dev signal must not beat the strong staging signal.
        assert_eq!(detect(&i).environment, Environment::Staging);
    }

    #[test]
    fn substrings_do_not_produce_false_matches() {
        // "development" appears nowhere as a token here.
        let info = detect(&inputs("devops-prod.example.com", "app"));
        assert_eq!(info.environment, Environment::Production);
    }

    #[test]
    fn urls_parse_without_retaining_the_password() {
        let t = ConnectionTarget::from_url(
            "postgresql://postgres.abcdefghijklmnopqrst:sekrit@aws-0-eu-west-2.pooler.supabase.com:6543/postgres?sslmode=require",
        )
        .expect("parses");
        assert_eq!(t.host, "aws-0-eu-west-2.pooler.supabase.com");
        assert_eq!(t.port, 6543);
        assert_eq!(t.database, "postgres");
        assert_eq!(t.user, "postgres.abcdefghijklmnopqrst");
        let serialized = serde_json::to_string(&t).unwrap();
        assert!(!serialized.contains("sekrit"));
    }

    #[test]
    fn declared_production_refs_are_certain() {
        let mut i = inputs("db.abcdefghijklmnopqrst.supabase.co", "postgres");
        i.production_project_refs = vec!["abcdefghijklmnopqrst".to_string()];
        let info = detect(&i);
        assert_eq!(info.confidence, Confidence::Certain);
    }
}
