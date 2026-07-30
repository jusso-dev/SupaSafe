# Configuration

SupaSafe runs with no configuration at all. Everything here is optional.

```sh
supasafe init                 # writes supasafe.toml with the defaults spelled out
supasafe doctor               # checks the config and reports anything surprising
```

It is read from the first of these that exists: `./supasafe.toml`,
`./.supasafe.toml`, `~/.supasafe/supasafe.toml`. Override with `--config` or
`SUPASAFE_CONFIG`.

## `[proxy]`

```toml
[proxy]
listen = "127.0.0.1:6432"          # where agents connect
upstream_tls = true                # require TLS to the database
upstream_ca = "/path/to/ca.pem"    # verify against this CA instead of public roots
tls_cert = "/path/to/cert.pem"     # offer TLS to connecting agents
tls_key = "/path/to/key.pem"
idle_timeout_seconds = 3600
introspection_url = "postgresql://supasafe_readonly:...@host/db"
```

`listen` defaults to loopback. An agent on your machine can reach it; the
network cannot. Change that deliberately.

`upstream_tls` is on by default and skipped automatically for loopback and Unix
socket connections, where there is no network to protect. It governs the
introspection connection too, so there are not two TLS settings that can
disagree with each other.

`introspection_url` is the one setting worth adding. Without it, blast radius is
a structural estimate. With it, SupaSafe connects on startup and every five
minutes, reads `pg_class`, `pg_constraint` and `pg_index`, and reports real row
counts and real cascade paths. Give it a read-only role:

```sql
CREATE ROLE supasafe_readonly LOGIN PASSWORD '...';
GRANT pg_read_all_stats TO supasafe_readonly;
GRANT USAGE ON SCHEMA public TO supasafe_readonly;
```

The introspection connection is separate from the ones agents use. It carries
no agent statements, and it authenticates with its own credentials over
SCRAM-SHA-256, MD5, cleartext or trust. It is also what snapshots run under, so
this is the role that needs enough access to `pg_dump` what you want captured.

When it cannot connect, SupaSafe logs a warning, carries on with structural
estimates, and marks every approval card `measured: false`. It does not refuse
to start, and it does not present guesses as measurements.

## `[server]`

```toml
[server]
listen = "127.0.0.1:7717"
open_browser = false
allow_policy_editing = true
```

The dashboard, and the approval API. The approve endpoint is the one thing in
SupaSafe that turns a refusal into an execution, so exposing it to a network is
a decision to make on purpose.

`allow_policy_editing` controls whether rules can be changed from the dashboard.
On by default, because tuning a rule you cannot try out is guesswork. Turn it
off if the dashboard is reachable from anywhere but your own machine: an edit
there changes what the proxy lets through, on the next statement.

With it off, the dashboard still shows every rule and still lets you test SQL
against them. It just will not save.

## `[audit]`

```toml
[audit]
path = "~/.supasafe/audit.jsonl"
store_raw_sql = false
stdout_json = false
```

`store_raw_sql = false` means records hold normalised SQL: `WHERE email = ?`
rather than the address. Turn it on only if you need the literals and have
protected the file, because an audit log that copies every value is a second
copy of the data you are guarding.

`stdout_json` also writes each record to stdout as JSON, for shipping to a log
pipeline.

## `[approvals]`

```toml
[approvals]
timeout_seconds = 300
allow_edit = true
require_distinct_approver = true
```

`require_distinct_approver` stops the requesting agent approving its own
request. Leave it on.

A per-policy `approval_timeout_seconds` overrides `timeout_seconds` for
statements governed by that policy.

## `[snapshots]`

```toml
[snapshots]
directory = "~/.supasafe/snapshots"
pg_dump_path = "pg_dump"
prefer_table_scope = true
timeout_seconds = 900
```

Snapshots use the introspection connection rather than borrowing an agent's
credentials. Without one, SupaSafe records a point-in-time marker instead: no
data is copied, but the timestamp to recover to is written down and shown on the
approval card.

## `[context]`

```toml
[context]
enabled = true
extra_instructions = [
  "Never touch the billing schema. Finance reconciles it nightly.",
  "Migrations live in supabase/migrations. Apply them with the CLI, not by hand.",
]
```

Project rules appended to the standing instructions SupaSafe serves over MCP and
prints with `supasafe context`.

## `[[database]]`

Declaring your databases removes the guesswork from environment detection.

```toml
[[database]]
name = "acme-prod"
host = "db.abcdefgh.supabase.co"        # supports * globs
environment = "production"
policy = "regulated"

[[database]]
name = "acme-staging"
project_ref = "ijklmnopqrstuvwxyzab"
environment = "staging"

[[database]]
name = "local"
host = "127.0.0.1"
database = "myapp_dev"
environment = "local"
```

You can also list production project references without a full entry:

```toml
production_project_refs = ["abcdefghijklmnopqrst"]
```

## Environment detection

Used when no `[[database]]` entry matches. Signals are collected with a
confidence, the highest tier wins, and within a tier the most severe environment
wins.

| Signal | Suggests | Confidence |
|---|---|---|
| `[[database]].environment` | as declared | certain |
| `SUPASAFE_ENV` | as set | certain |
| A project reference in `production_project_refs` | production | certain |
| A hosted Supabase project | production | strong |
| Loopback, `.local`, `host.docker.internal`, a Unix socket | local | strong |
| Host name containing `prod`, `production`, `live`, `main` | production | strong |
| Host name containing `staging`, `stage`, `qa`, `uat`, `preview`, `test` | staging | strong |
| Host name containing `dev`, `sandbox`, `scratch` | development | weak |
| Database name containing any of the above | as above | weak |
| `NODE_ENV`, `APP_ENV`, `RAILS_ENV`, `VERCEL_ENV`, `RAILWAY_ENVIRONMENT` | as set | weak |

Name matching is per component, not substring, so `devops-prod.example.com`
reads as production rather than development.

**Nothing matched?** Production. The cost of being wrong is not symmetric: guess
production and you get an approval prompt, guess development and you get an
outage.

## Environment variables

| Variable | Effect |
|---|---|
| `SUPASAFE_CONFIG` | Path to the config file |
| `SUPASAFE_UPSTREAM` | Default `--upstream` |
| `SUPASAFE_ENV` | Force the environment |
| `SUPASAFE_HOME` | State directory, default `~/.supasafe` |
| `SUPASAFE_LOG` | Log filter, e.g. `supasafe=debug` |
| `NO_COLOR` | Turn off colour |

## A complete example

```toml
production_project_refs = ["abcdefghijklmnopqrst"]

[proxy]
listen = "127.0.0.1:6432"
introspection_url = "postgresql://supasafe_readonly:hunter2@db.abcdefgh.supabase.co:5432/postgres"

[audit]
path = "/var/log/supasafe/audit.jsonl"
stdout_json = true

[context]
extra_instructions = ["Never touch the billing schema."]

[[database]]
name = "acme-prod"
host = "db.abcdefgh.supabase.co"
environment = "production"
policy = "production"

[[policies.production.rules]]
name = "billing-is-off-limits"
action = "deny"
message = "The billing schema is reconciled nightly. Changes go through finance."
when = { objects = ["billing.*"], categories = ["write", "ddl"] }
```

Rules you add are appended to the built-in ones, so put anything that must win
where you want it in the order and check with `supasafe policy production`.
