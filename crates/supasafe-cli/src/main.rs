//! `supasafe` — the command line interface.
//!
//! The commands are the ones you actually reach for:
//!
//! * `supasafe start` — proxy and dashboard together, the normal way to run it
//! * `supasafe proxy` — the proxy alone
//! * `supasafe analyze` — judge a statement without a database in sight
//! * `supasafe approve` — answer a held statement from a terminal
//! * `supasafe audit` — read the trail, and prove it has not been edited

#![forbid(unsafe_code)]

mod format;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use supasafe_core::approval::{ApprovalSettings, ApprovalStore};
use supasafe_core::audit::AuditLog;
use supasafe_core::config::Config;
use supasafe_core::environment::ConnectionTarget;
use supasafe_core::guard::{Guard, Request};
use supasafe_core::snapshot::{SnapshotManager, SnapshotSettings};
use supasafe_proxy::tls::{TlsClientConfig, TlsServerConfig};
use supasafe_proxy::{Proxy, ProxyConfig};

#[derive(Parser)]
#[command(
    name = "supasafe",
    version,
    about = "AI Database Safety Guard for PostgreSQL and Supabase",
    long_about = "SupaSafe sits between your AI coding agents and PostgreSQL. It parses every \
                  statement, scores it, and refuses the ones that would destroy your data.\n\n\
                  Start with:  supasafe start --upstream <your database url>"
)]
struct Cli {
    /// Path to supasafe.toml. Defaults to ./supasafe.toml, then ~/.supasafe/supasafe.toml.
    #[arg(long, short, global = true, env = "SUPASAFE_CONFIG")]
    config: Option<PathBuf>,

    /// Print machine-readable JSON instead of formatted output.
    #[arg(long, global = true)]
    json: bool,

    /// Show more detail about what SupaSafe is doing.
    #[arg(long, short, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy and the dashboard together.
    Start {
        /// The database to protect, as a PostgreSQL URL.
        #[arg(long, env = "SUPASAFE_UPSTREAM")]
        upstream: String,
        /// Where agents connect.
        #[arg(long)]
        listen: Option<String>,
        /// Where the dashboard listens.
        #[arg(long)]
        dashboard: Option<String>,
    },

    /// Run only the proxy.
    Proxy {
        #[arg(long, env = "SUPASAFE_UPSTREAM")]
        upstream: String,
        #[arg(long)]
        listen: Option<String>,
    },

    /// Run only the dashboard and approval API.
    Serve {
        #[arg(long)]
        listen: Option<String>,
    },

    /// Analyse SQL and report what SupaSafe would do with it.
    Analyze {
        /// The SQL. Reads standard input when omitted.
        sql: Option<String>,
        /// Judge it as if it were going to this database.
        #[arg(long)]
        target: Option<String>,
        /// Force an environment instead of detecting one.
        #[arg(long)]
        environment: Option<String>,
        /// Read the statement from a file.
        #[arg(long, short)]
        file: Option<PathBuf>,
    },

    /// Answer statements that are waiting for a human.
    Approve {
        /// The request to answer. Lists everything pending when omitted.
        id: Option<String>,
        /// Who is answering.
        #[arg(long, env = "USER")]
        approver: Option<String>,
        /// Refuse instead of approving.
        #[arg(long)]
        reject: bool,
        /// Why it was refused.
        #[arg(long)]
        reason: Option<String>,
        /// Approve this statement instead of the one that was asked for.
        #[arg(long)]
        edit: Option<String>,
        /// The dashboard to talk to.
        #[arg(long, default_value = "http://127.0.0.1:7717")]
        server: String,
    },

    /// Read the audit trail.
    Audit {
        /// How many records to show.
        #[arg(long, default_value_t = 25)]
        limit: usize,
        /// Check that the chain has not been edited, and stop.
        #[arg(long)]
        verify: bool,
        /// Only records with this decision.
        #[arg(long)]
        decision: Option<String>,
        /// Only records at or above this risk score.
        #[arg(long)]
        min_risk: Option<u8>,
    },

    /// Explain the policies in force.
    Policy {
        /// Show the rules of one policy in full.
        name: Option<String>,
    },

    /// Write a starter supasafe.toml.
    Init {
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// Where to write it.
        #[arg(long, default_value = "supasafe.toml")]
        output: PathBuf,
    },

    /// Print the safety instructions to give your agents.
    Context {
        /// The database the agent will be working against.
        #[arg(long)]
        target: Option<String>,
    },

    /// Run the MCP server on stdio, for agents that can ask before they act.
    Mcp {
        /// The database the agent is working against.
        #[arg(long, env = "SUPASAFE_UPSTREAM")]
        upstream: Option<String>,
    },

    /// Check the configuration and report anything that would surprise you.
    Doctor,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.json);

    match run(cli).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{} {e:#}", format::red("error:"));
            std::process::exit(1);
        }
    }
}

fn init_tracing(verbose: bool, json: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("SUPASAFE_LOG").unwrap_or_else(|_| {
        EnvFilter::new(if verbose {
            "supasafe=debug,info"
        } else {
            "warn"
        })
    });
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // Logs go to stderr so `--json` output on stdout stays parseable.
        .with_writer(std::io::stderr);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// Returns the process exit code.
async fn run(cli: Cli) -> Result<i32> {
    let config = load_config(cli.config.as_deref())?;

    match cli.command {
        Command::Start {
            upstream,
            listen,
            dashboard,
        } => start(config, &upstream, listen, dashboard, true).await,

        Command::Proxy { upstream, listen } => start(config, &upstream, listen, None, false).await,

        Command::Serve { listen } => {
            let guard = build_guard(&config)?;
            let addr = listen
                .unwrap_or_else(|| config.server.listen.clone())
                .parse()
                .context("the dashboard address is not a valid host:port")?;
            println!("{} dashboard on http://{addr}", format::green("→"));
            supasafe_server::serve(addr, guard).await?;
            Ok(0)
        }

        Command::Analyze {
            sql,
            target,
            environment,
            file,
        } => analyze(&config, sql, file, target, environment, cli.json),

        Command::Approve {
            id,
            approver,
            reject,
            reason,
            edit,
            server,
        } => approve(id, approver, reject, reason, edit, &server, cli.json).await,

        Command::Audit {
            limit,
            verify,
            decision,
            min_risk,
        } => audit(&config, limit, verify, decision, min_risk, cli.json),

        Command::Policy { name } => policy(&config, name, cli.json),

        Command::Init { force, output } => init(&output, force),

        Command::Context { target } => {
            let guard = build_guard(&config)?;
            let target = parse_target(target.as_deref())?;
            println!("{}", guard.agent_context(&target));
            Ok(0)
        }

        Command::Mcp { upstream } => {
            let guard = build_guard(&config)?;
            let target = parse_target(upstream.as_deref())?;
            let snapshots = build_snapshots(&config, upstream.as_deref());
            let server = Arc::new(supasafe_mcp::McpServer::new(guard, snapshots, target));
            server.serve_stdio().await?;
            Ok(0)
        }

        Command::Doctor => doctor(&config, cli.json),
    }
}

fn load_config(path: Option<&std::path::Path>) -> Result<Config> {
    match path {
        Some(p) => Config::load(p).with_context(|| format!("reading {}", p.display())),
        None => Config::load_or_default().context("reading the configuration"),
    }
}

fn build_guard(config: &Config) -> Result<Arc<Guard>> {
    let compiled = config
        .compile()
        .context("the policy configuration is not valid")?;

    let audit = AuditLog::open(&config.audit.path, config.audit.store_raw_sql)
        .with_context(|| format!("opening the audit log at {}", config.audit.path.display()))?
        .with_stdout_json(config.audit.stdout_json);

    let approvals = ApprovalStore::new(ApprovalSettings {
        timeout_seconds: config.approvals.timeout_seconds,
        allow_edit: config.approvals.allow_edit,
        require_distinct_approver: config.approvals.require_distinct_approver,
    });

    Ok(Arc::new(Guard::new(compiled, Arc::new(audit), approvals)))
}

fn build_snapshots(config: &Config, upstream: Option<&str>) -> Arc<SnapshotManager> {
    Arc::new(SnapshotManager::new(
        SnapshotSettings {
            directory: config.snapshots.directory.clone(),
            pg_dump_path: config.snapshots.pg_dump_path.clone(),
            prefer_table_scope: config.snapshots.prefer_table_scope,
            timeout_seconds: config.snapshots.timeout_seconds,
        },
        // Snapshots use the introspection connection, which is a role you
        // grant deliberately, rather than borrowing an agent's credentials.
        config
            .proxy
            .introspection_url
            .clone()
            .or_else(|| upstream.map(|s| s.to_string())),
    ))
}

fn parse_target(url: Option<&str>) -> Result<ConnectionTarget> {
    match url {
        Some(url) => ConnectionTarget::from_url(url)
            .with_context(|| format!("{url:?} is not a PostgreSQL URL")),
        None => Ok(ConnectionTarget::default()),
    }
}

async fn start(
    config: Config,
    upstream: &str,
    listen: Option<String>,
    dashboard: Option<String>,
    with_dashboard: bool,
) -> Result<i32> {
    let target = ConnectionTarget::from_url(upstream)
        .with_context(|| format!("{upstream:?} is not a PostgreSQL URL"))?;

    let guard = build_guard(&config)?;
    let snapshots = build_snapshots(&config, Some(upstream));

    let listen_addr: std::net::SocketAddr = listen
        .unwrap_or_else(|| config.proxy.listen.clone())
        .parse()
        .context("the proxy listen address is not a valid host:port")?;

    // TLS to the database, unless the operator turned it off. Talking to a
    // hosted database in the clear should not be something you can do by
    // forgetting a flag.
    let client_tls = if config.proxy.upstream_tls && !is_loopback(&target.host) {
        Some(match &config.proxy.upstream_ca {
            Some(ca) => TlsClientConfig::with_custom_ca(ca)?,
            None => TlsClientConfig::with_webpki_roots()?,
        })
    } else {
        None
    };

    let server_tls = match (&config.proxy.tls_cert, &config.proxy.tls_key) {
        (Some(cert), Some(key)) => Some(TlsServerConfig::from_pem(cert, key)?),
        _ => None,
    };

    let proxy = Arc::new(Proxy::new(
        ProxyConfig {
            listen: listen_addr,
            upstream_host: target.host.clone(),
            upstream_port: target.port,
            server_tls,
            client_tls,
        },
        guard.clone(),
        snapshots,
    ));
    let listener = proxy.bind().await?;

    let info = guard.config().classify(&target);
    let policy = guard.config().policy_for(&info);

    format::banner(&info, policy.name(), &listen_addr.to_string());

    if with_dashboard {
        let dashboard_addr: std::net::SocketAddr = dashboard
            .unwrap_or_else(|| config.server.listen.clone())
            .parse()
            .context("the dashboard address is not a valid host:port")?;
        println!("  {} dashboard   http://{dashboard_addr}", format::dim("│"));
        let guard_for_server = guard.clone();
        tokio::spawn(async move {
            if let Err(e) = supasafe_server::serve(dashboard_addr, guard_for_server).await {
                tracing::error!(error = %e, "the dashboard stopped");
            }
        });
    }

    println!();
    proxy.serve(listener).await?;
    Ok(0)
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.starts_with("127.") || host == "::1" || host.starts_with('/')
}

fn analyze(
    config: &Config,
    sql: Option<String>,
    file: Option<PathBuf>,
    target: Option<String>,
    environment: Option<String>,
    json: bool,
) -> Result<i32> {
    let sql = match (sql, file) {
        (Some(sql), _) => sql,
        (None, Some(path)) => {
            std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?
        }
        (None, None) => {
            use std::io::Read;
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .context("reading SQL from standard input")?;
            buffer
        }
    };

    if sql.trim().is_empty() {
        anyhow::bail!("no SQL was given");
    }

    let mut config = config.clone();
    if let Some(env) = &environment {
        let parsed = supasafe_core::environment::Environment::parse(env).with_context(|| {
            format!("{env:?} is not one of local, development, staging, production")
        })?;
        config
            .databases
            .push(supasafe_core::config::DatabaseConfig {
                name: "cli-override".into(),
                host: Some("*".into()),
                environment: Some(parsed),
                ..Default::default()
            });
    }

    // `analyze` is advisory and leaves no trace: it is how you ask a question,
    // not how you do something.
    let guard = Guard::new(
        config.compile()?,
        Arc::new(AuditLog::in_memory()),
        ApprovalStore::new(ApprovalSettings::default()),
    );

    let target = parse_target(target.as_deref())?;
    let request = Request::new(sql).from_agent("supasafe-cli");
    let verdict = guard.evaluate(&request, &target);

    if json {
        println!("{}", serde_json::to_string_pretty(&verdict)?);
    } else {
        format::verdict(&verdict);
    }

    // A non-zero exit code makes this usable in CI and in a pre-commit hook.
    Ok(if verdict.blocks_execution() { 1 } else { 0 })
}

async fn approve(
    id: Option<String>,
    approver: Option<String>,
    reject: bool,
    reason: Option<String>,
    edit: Option<String>,
    server: &str,
    json: bool,
) -> Result<i32> {
    let base = server.trim_end_matches('/');

    let Some(id) = id else {
        let body = http_get(&format!("{base}/api/approvals")).await?;
        let approvals = body["approvals"].as_array().cloned().unwrap_or_default();
        let pending: Vec<&serde_json::Value> = approvals
            .iter()
            .filter(|a| a["state"]["state"] == "pending")
            .collect();

        if json {
            println!("{}", serde_json::to_string_pretty(&pending)?);
        } else if pending.is_empty() {
            println!("Nothing is waiting for approval.");
        } else {
            format::pending_list(&pending);
        }
        return Ok(0);
    };

    let approver = approver.unwrap_or_else(|| "unknown".to_string());
    let (action, body) = if reject {
        (
            "reject",
            serde_json::json!({ "approver": approver, "reason": reason }),
        )
    } else if let Some(sql) = edit {
        (
            "edit",
            serde_json::json!({ "approver": approver, "sql": sql }),
        )
    } else {
        ("approve", serde_json::json!({ "approver": approver }))
    };

    let response = http_post(&format!("{base}/api/approvals/{id}/{action}"), &body).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        let state = response["state"]["state"].as_str().unwrap_or("unknown");
        println!("{} request {id} is now {state}", format::green("✓"));
    }
    Ok(0)
}

fn audit(
    config: &Config,
    limit: usize,
    verify: bool,
    decision: Option<String>,
    min_risk: Option<u8>,
    json: bool,
) -> Result<i32> {
    let log = AuditLog::open(&config.audit.path, config.audit.store_raw_sql)
        .with_context(|| format!("opening {}", config.audit.path.display()))?;

    if verify {
        let result = log.verify()?;
        if json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else if result.is_intact() {
            println!(
                "{} {} record(s), chain intact",
                format::green("✓"),
                result.records
            );
            if let Some(head) = &result.head {
                println!("  head {}", format::dim(&head[..16]));
            }
        } else {
            println!(
                "{} the audit chain is broken in {} place(s)",
                format::red("✗"),
                result.breaks.len()
            );
            for b in &result.breaks {
                println!("  record {}: {}", b.seq, b.problem);
            }
        }
        return Ok(if result.is_intact() { 0 } else { 1 });
    }

    let mut records = log.records()?;
    records.reverse();
    let filtered: Vec<_> = records
        .into_iter()
        .filter(|r| {
            decision
                .as_ref()
                .map(|d| r.decision.as_str() == d)
                .unwrap_or(true)
        })
        .filter(|r| min_risk.map(|m| r.risk >= m).unwrap_or(true))
        .take(limit)
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
    } else if filtered.is_empty() {
        println!(
            "No audit records yet. The trail lives at {}.",
            config.audit.path.display()
        );
    } else {
        format::audit_table(&filtered);
    }
    Ok(0)
}

fn policy(config: &Config, name: Option<String>, json: bool) -> Result<i32> {
    let compiled = config.compile()?;

    match name {
        Some(name) => {
            let policy = compiled
                .policy(&name)
                .with_context(|| format!("no policy named {name:?}"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&policy.policy)?);
            } else {
                format::policy_detail(&policy.policy);
            }
        }
        None => {
            if json {
                println!("{}", serde_json::to_string_pretty(&config.policies)?);
            } else {
                for policy in compiled.policies() {
                    println!(
                        "{:<14} {}",
                        format::bold(policy.name()),
                        policy.policy.description
                    );
                }
                println!();
                println!("{}", format::dim("supasafe policy <name> shows the rules"));
            }
        }
    }
    Ok(0)
}

fn init(output: &std::path::Path, force: bool) -> Result<i32> {
    if output.exists() && !force {
        anyhow::bail!(
            "{} already exists. Pass --force to overwrite it.",
            output.display()
        );
    }
    let config = Config::default();
    let mut text = String::from(
        "# SupaSafe configuration.\n\
         #\n\
         # Everything here has a default, so you can delete anything you do not\n\
         # want to change. The policies below are the ones SupaSafe ships with;\n\
         # they are written out in full so you can see exactly what is being\n\
         # enforced, and edit it.\n\
         #\n\
         # Docs: https://github.com/jusso-dev/supasafe/blob/main/docs/configuration.md\n\n",
    );
    text.push_str(&config.to_toml());
    std::fs::write(output, text).with_context(|| format!("writing {}", output.display()))?;
    println!("{} wrote {}", format::green("✓"), output.display());
    println!("  Next: supasafe start --upstream postgresql://...");
    Ok(0)
}

fn doctor(config: &Config, json: bool) -> Result<i32> {
    let mut findings: Vec<(bool, String)> = Vec::new();

    match config.compile() {
        Ok(compiled) => findings.push((
            true,
            format!("{} policies compile", compiled.policy_names().len()),
        )),
        Err(e) => findings.push((false, format!("the policy configuration is invalid: {e}"))),
    }

    match AuditLog::open(&config.audit.path, config.audit.store_raw_sql) {
        Ok(log) => match log.verify() {
            Ok(v) if v.is_intact() => {
                findings.push((true, format!("audit chain intact ({} records)", v.records)))
            }
            Ok(v) => findings.push((
                false,
                format!("the audit chain is broken in {} place(s)", v.breaks.len()),
            )),
            Err(e) => findings.push((false, format!("the audit log could not be read: {e}"))),
        },
        Err(e) => findings.push((false, format!("the audit log could not be opened: {e}"))),
    }

    if config.audit.store_raw_sql {
        findings.push((
            false,
            "audit.store_raw_sql is on, so literal values from your queries are written to the \
             audit log. Leave it off unless you need it and have protected the file."
                .to_string(),
        ));
    } else {
        findings.push((
            true,
            "audit records store normalised SQL, not literals".into(),
        ));
    }

    if config.proxy.introspection_url.is_some() {
        findings.push((
            true,
            "an introspection connection is configured, so row estimates and cascade analysis are \
             measured"
                .into(),
        ));
    } else {
        findings.push((
            false,
            "no proxy.introspection_url is set, so blast radius numbers are structural estimates \
             rather than measurements"
                .to_string(),
        ));
    }

    if !config.proxy.upstream_tls {
        findings.push((
            false,
            "proxy.upstream_tls is off, so the connection to your database is not encrypted"
                .to_string(),
        ));
    }

    if config.databases.is_empty() {
        findings.push((
            false,
            "no databases are declared, so SupaSafe will detect environments from connection \
             strings. Declaring your production database removes the guesswork."
                .to_string(),
        ));
    }

    if json {
        let items: Vec<_> = findings
            .iter()
            .map(|(ok, m)| serde_json::json!({ "ok": ok, "message": m }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        for (ok, message) in &findings {
            println!(
                "{} {message}",
                if *ok {
                    format::green("✓")
                } else {
                    format::amber("!")
                }
            );
        }
    }

    // Advice is not failure: doctor reports, it does not gate.
    Ok(0)
}

// --- a very small HTTP client -------------------------------------------
//
// The CLI makes one or two requests to a dashboard on loopback. That does not
// justify pulling a full HTTP client and a second TLS stack into the binary,
// so this speaks just enough HTTP/1.1 to do the job.

async fn http_get(url: &str) -> Result<serde_json::Value> {
    http_request("GET", url, None).await
}

async fn http_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    http_request("POST", url, Some(body)).await
}

async fn http_request(
    method: &str,
    url: &str,
    body: Option<&serde_json::Value>,
) -> Result<serde_json::Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rest = url
        .strip_prefix("http://")
        .context("only http:// is supported for the local dashboard")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };

    let mut stream = tokio::net::TcpStream::connect(&addr)
        .await
        .with_context(|| {
            format!(
                "could not reach the SupaSafe dashboard at {addr}. Is `supasafe start` running?"
            )
        })?;

    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\
         Accept: application/json\r\n"
    );
    if body.is_some() {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    }
    request.push_str("\r\n");
    request.push_str(&payload);

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8_lossy(&response);

    let (head, body) = text
        .split_once("\r\n\r\n")
        .context("the dashboard sent a malformed response")?;

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);

    let value: serde_json::Value =
        serde_json::from_str(body.trim()).unwrap_or(serde_json::Value::Null);

    if !(200..300).contains(&status) {
        let message = value["error"]
            .as_str()
            .unwrap_or("the dashboard refused the request");
        anyhow::bail!("{message}");
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_documented_commands_all_exist() {
        let command = Cli::command();
        let names: Vec<&str> = command.get_subcommands().map(|s| s.get_name()).collect();
        for expected in [
            "start", "proxy", "serve", "analyze", "approve", "audit", "policy", "init", "context",
            "mcp", "doctor",
        ] {
            assert!(names.contains(&expected), "missing command: {expected}");
        }
    }

    #[test]
    fn analyze_accepts_bare_sql() {
        let cli = Cli::try_parse_from(["supasafe", "analyze", "DROP TABLE users"]).unwrap();
        match cli.command {
            Command::Analyze { sql, .. } => assert_eq!(sql.as_deref(), Some("DROP TABLE users")),
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn start_requires_an_upstream() {
        assert!(Cli::try_parse_from(["supasafe", "start"]).is_err());
        assert!(Cli::try_parse_from([
            "supasafe",
            "start",
            "--upstream",
            "postgresql://localhost/app"
        ])
        .is_ok());
    }

    #[test]
    fn analyze_exits_non_zero_when_a_statement_would_be_blocked() {
        let config = Config::default();
        let blocked = analyze(
            &config,
            Some("DROP TABLE users".into()),
            None,
            Some("postgresql://postgres@db.abcdefghijklmnopqrst.supabase.co/postgres".into()),
            None,
            true,
        )
        .unwrap();
        assert_eq!(blocked, 1);

        let allowed = analyze(
            &config,
            Some("SELECT 1".into()),
            None,
            Some("postgresql://postgres@db.abcdefghijklmnopqrst.supabase.co/postgres".into()),
            None,
            true,
        )
        .unwrap();
        assert_eq!(allowed, 0);
    }

    #[test]
    fn the_environment_can_be_forced() {
        // The same statement that is blocked above runs when the operator says
        // this is a development database.
        let code = analyze(
            &Config::default(),
            Some("DROP TABLE users".into()),
            None,
            Some("postgresql://postgres@db.abcdefghijklmnopqrst.supabase.co/postgres".into()),
            Some("development".into()),
            true,
        )
        .unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn loopback_detection_covers_the_usual_forms() {
        assert!(is_loopback("localhost"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("/var/run/postgresql"));
        assert!(!is_loopback("db.abc.supabase.co"));
    }
}
