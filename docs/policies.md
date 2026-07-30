# Policies

A policy answers one question: given this statement, this score and this
environment, what happens?

Four actions, in order of severity:

| Action | Effect |
|---|---|
| `allow` | Forwarded. |
| `warn` | Forwarded, with a `WARNING` the client sees, and recorded. |
| `require_approval` | Held until a human answers or it times out. |
| `deny` | Refused. The statement never reaches the database. |

## How a decision is reached

1. **Guards.** `protect_managed_surfaces` and `deny_unparsed` run before
   anything else. They cannot be overridden by a rule, only turned off in
   configuration. A blanket `allow` rule does not open the `auth` schema.
2. **Rules, in order.** The first match wins. A rule's action is used exactly as
   written, because an operator who wrote a rule was being explicit.
3. **Default, escalated.** If no rule matched, start from `default` and escalate
   through `warn_above`, `require_approval_above` and `deny_above`. Escalation
   only ever increases severity.

The ordering means an allow-list works the way you expect: put your `allow`
rules first, end with a catch-all, and set `default = "deny"` so anything you
did not think of is refused rather than permitted.

## Writing a policy

```toml
[policies.my-policy]
description = "What this policy is for. Shown in the CLI and the dashboard."
default = "deny"

warn_above = 25
require_approval_above = 50
deny_above = 95

approvals_required = 1
approval_timeout_seconds = 300

snapshot_above = 80          # take a recovery point before executing
dry_run_above = 50           # run EXPLAIN before executing

deny_unparsed = true
protect_managed_surfaces = true

[[policies.my-policy.rules]]
name = "allow-reads"
action = "allow"
message = "Reads do not change anything."
when = { categories = ["read"] }
```

## Matchers

Every field that is set must match. Fields left out do not constrain.

| Field | Matches |
|---|---|
| `kinds` | Statement kinds: `["drop_table", "truncate", "update"]` |
| `categories` | Families: `read`, `write`, `ddl`, `dcl`, `maintenance`, `transaction`, `session`, `execute` |
| `objects` | Glob against `schema.object`: `["auth.*", "public.audit_*"]` |
| `schemas` | Schema names |
| `surfaces` | Managed surfaces: `["supabase_auth", "supabase_storage"]` |
| `flags` | Every listed flag must be set |
| `any_flags` | At least one listed flag must be set |
| `min_risk` / `max_risk` | Score bounds, inclusive |
| `level` | Risk band: `low`, `moderate`, `high`, `critical`, `catastrophic` |
| `unfiltered` | `true` matches writes with no effective `WHERE` |
| `unparsed` | `true` matches statements the grammar rejected |
| `environments` | `["production", "staging"]` |
| `agents` | Glob against the client's `application_name`: `["claude-*"]` |

Bad globs and unknown actions fail when the policy loads, not when a request
arrives. A rule that silently never matches is worse than no rule.

## Flags

Extracted from the AST, available to `flags` and `any_flags`:

| Flag | Meaning |
|---|---|
| `cascade` | `CASCADE` was specified |
| `drops_column` | `ALTER TABLE ... DROP COLUMN` |
| `drops_constraint` | Dropping a constraint, foreign key or primary key |
| `changes_column_type` | `ALTER COLUMN ... TYPE`, which rewrites the table |
| `changes_owner` | `OWNER TO` |
| `renames` | Renaming a table, column or constraint |
| `weakens_rls` | `DISABLE ROW LEVEL SECURITY`, or dropping a policy |
| `strengthens_rls` | `ENABLE`/`FORCE ROW LEVEL SECURITY`, or creating a policy |
| `disables_trigger` | `DISABLE TRIGGER` |
| `grants_elevated_role` | `SUPERUSER`, `BYPASSRLS`, `REPLICATION`, `CREATEROLE` |
| `grants_all` | `GRANT ALL` |
| `grants_to_public` | Grantee is `PUBLIC`, `anon` or `authenticated` |
| `copy_program` | `COPY ... TO/FROM PROGRAM` |
| `copy_file` | `COPY` to or from a server-side path |
| `security_definer` | `SECURITY DEFINER` routine |
| `opaque_body` | A body static analysis cannot see into |
| `opaque_body_is_destructive` | That body contains destructive statements |
| `returning` | `RETURNING` |
| `multi_table` | Writes across more than one table |
| `locking_read` | `SELECT ... FOR UPDATE` |
| `unparsed` | Classified lexically rather than parsed |
| `if_exists`, `or_replace`, `concurrently`, `only`, `adds_column`, `sets_not_null`, `select_into` | As written |

## Worked examples

**Protect a schema absolutely.**

```toml
[[policies.production.rules]]
name = "billing-is-off-limits"
action = "deny"
message = "The billing schema is reconciled nightly. Changes go through finance."
when = { objects = ["billing.*"], categories = ["write", "ddl"] }
```

Put it near the top: rules are ordered, and a later `allow-scoped-writes` would
otherwise let a scoped update through.

**Let one trusted agent do migrations without a prompt.**

```toml
[[policies.production.rules]]
name = "migration-runner"
action = "allow"
message = "The migration runner is reviewed in CI before it ever connects."
when = { agents = ["migration-runner"], categories = ["ddl"], max_risk = 79 }
```

`application_name` is not authentication. Anyone who can connect can claim any
name, so this is a convenience for a trusted network, not a security boundary.

**Require two people for anything touching money.**

```toml
[[policies.production.rules]]
name = "money-needs-two-people"
action = "require_approval"
approvals = 2
message = "Financial data needs a second pair of eyes."
when = { objects = ["public.payments", "public.invoices", "public.ledger_*"] }
```

**Allow a nightly cleanup job that would otherwise be held.**

```toml
[[policies.production.rules]]
name = "session-reaper"
action = "allow"
message = "Expiring old sessions is routine and bounded."
when = { kinds = ["delete"], objects = ["public.sessions"], unfiltered = false, max_risk = 79 }
```

**Refuse anything an agent could not explain.**

```toml
[[policies.production.rules]]
name = "no-dynamic-sql"
action = "deny"
message = "SupaSafe cannot see inside a DO block or a dynamic EXECUTE. Write the statements out."
when = { any_flags = ["opaque_body"] }
```

## Editing rules from the dashboard

Everything in this document can also be done at `http://127.0.0.1:7717`, under
**Rules the proxy enforces**. The two are the same thing: the dashboard writes
to `supasafe.toml`, and a change made either way applies to the next statement
without a restart.

The dashboard adds one thing the file cannot: a **Test** box inside the rule
editor. Paste a statement and see what happens with and without your draft
before you save it.

```
as it is now      allow    risk 0
with this rule    deny     risk 0 · matched "no-secrets"
```

When a draft rule does not change the outcome, it says so. That is usually
because an earlier rule already decided, which is the single most common
mistake when writing rules and the hardest to spot by reading.

### Ordering from the dashboard

The ↑ and ↓ buttons move a rule earlier or later. Rules are numbered because
the first match wins, so a rule that never seems to fire is normally sitting
behind one that already matched.

### What the API does

The dashboard has no privileges of its own; it calls the same endpoints you
can:

| | |
|---|---|
| `GET /api/policies` | every policy, its settings, and its rules in order |
| `GET /api/policies/vocabulary` | the kinds, categories, flags and actions a rule can use |
| `POST /api/policies/try` | evaluate SQL with and without a draft rule, changing nothing |
| `POST /api/policies/{policy}/rules` | add a rule (to the front by default) |
| `PUT /api/policies/{policy}/rules/{i}` | replace a rule |
| `DELETE /api/policies/{policy}/rules/{i}` | remove a rule |
| `POST /api/policies/{policy}/rules/{i}/move` | reorder, with `{"to": n}` |
| `PUT /api/policies/{policy}/settings` | thresholds and guards |
| `GET`/`PUT /api/config` | the whole file as TOML |
| `POST /api/config/reload` | re-read the file after a hand edit |

```sh
curl -X POST http://127.0.0.1:7717/api/policies/production/rules \
  -H 'content-type: application/json' \
  -d '{"name":"no-secrets","action":"deny",
       "message":"The secrets table is not for agents.",
       "when":{"objects":["public.secrets"]}}'
```

Every write is compiled before it is installed or saved. A glob with a syntax
error is a 400 and the running policy is untouched, so there is no path that
leaves the proxy enforcing something it cannot parse.

Turn the whole thing off with `allow_policy_editing = false` under `[server]`.
Rules stay visible and testable; they cannot be saved.

## Testing a policy

```sh
# Does this statement get through?
supasafe analyze "DELETE FROM sessions WHERE expires_at < now()" \
  --target "postgresql://...@db.abcdefgh.supabase.co/postgres"

# What does the policy actually say, in order?
supasafe policy production
```

`supasafe analyze` writes nothing to the audit trail and touches no database. It
exits non-zero when a statement would be blocked, which makes it usable as a CI
check over the migrations in a pull request.

## Choosing a policy per database

```toml
[[database]]
name = "acme-prod"
host = "db.abcdefgh.supabase.co"
environment = "production"
policy = "regulated"

[[database]]
name = "acme-staging"
project_ref = "ijklmnopqrstuvwxyzab"
environment = "staging"
```

Without an entry, the environment is detected and its default policy is used:
`local` and `development` get `development`, `staging` gets `staging`,
`production` gets `production`.
