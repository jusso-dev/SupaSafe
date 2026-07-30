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

## Quick start

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

Now an approval card says what will actually happen:

```
DELETE FROM users

  451,000 rows across 1 table, cascading into 2 more, holding an ACCESS EXCLUSIVE lock

  public.users         1,000 rows  →  0
  public.orders       50,000 rows  →  0   (via orders_user_fk, ON DELETE CASCADE)
  public.order_items 400,000 rows  →  0   (via items_order_fk, ON DELETE CASCADE)

  ! 2 tables will be modified through ON DELETE CASCADE without appearing
    in the statement
```

Without it, SupaSafe says so rather than inventing numbers.

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

## Everything else

| | |
|---|---|
| [Configuration](docs/configuration.md) | `supasafe.toml` in full |
| [Policies](docs/policies.md) | Writing rules, matchers, worked examples |
| [Risk engine](docs/risk.md) | How every score is derived |
| [Architecture](docs/architecture.md) | How the pieces fit, and the threat model |
| [Clients](docs/clients.md) | Setup for Claude Code, Codex, Cursor, Windsurf, Aider, Goose, OpenCode, Hermes |
| [VS Code extension](extensions/vscode) | Analyse a selection, approve from the editor |
| [Examples](examples) | Docker Compose, CI checks, sample configs |

## Building

```sh
cargo test --workspace          # 274 tests, no database needed

# the end-to-end tests drive a real psql against a real server
SUPASAFE_TEST_PG=postgresql://postgres@127.0.0.1:5432/postgres \
  cargo test -p supasafe-proxy --test end_to_end
```

Rust, with no `unsafe` anywhere in the workspace.

## Honest limitations

- Blast radius is a structural estimate until you give it a read-only connection. It tells you which one it is doing.
- Row estimates come from `pg_class.reltuples`, which is what the planner uses and is approximate by definition.
- Fast-path function calls (the binary protocol for calling a function by OID) are refused rather than analysed, because they carry no SQL. Modern clients only use them for large objects.
- A statement that passes policy is forwarded unchanged. SupaSafe decides whether something runs, not what it does once it is running.
- If an agent has credentials for the database directly, it can go around the proxy. Give agents the proxy's address and nothing else.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
