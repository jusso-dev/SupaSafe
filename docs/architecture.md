# Architecture

## The shape of it

```
   agent                     SupaSafe                        database
     │                          │                                │
     │  startup packet          │                                │
     ├─────────────────────────▶│  forwarded verbatim ──────────▶│
     │                          │                                │
     │  ◀── authentication relayed byte for byte, both ways ────▶ │
     │                          │                                │
     │  Query("DROP TABLE …")   │                                │
     ├─────────────────────────▶│                                │
     │                          │ parse → classify → score       │
     │                          │ → blast radius → policy        │
     │                          │                                │
     │  ◀── ErrorResponse ──────┤        (never forwarded)       │
     │  ◀── ReadyForQuery ──────┤                                │
```

SupaSafe is a PostgreSQL server as far as the client is concerned, and a
PostgreSQL client as far as the database is concerned. Statements that pass
policy are forwarded unchanged. Statements that do not are answered with an
`ErrorResponse` carrying SQLSTATE `42501`, which every client library already
handles.

## Crates

| Crate | Job |
|---|---|
| `supasafe-parser` | SQL to a semantic model. Statement kinds, objects, predicate analysis, flags. No regex. |
| `supasafe-core` | Environment detection, risk, blast radius, policy, rollback, snapshots, audit, approvals. `Guard` ties them together. |
| `supasafe-proxy` | The wire protocol, the session state machine, TLS, and a small read-only client for introspection. |
| `supasafe-server` | Dashboard and approval API. |
| `supasafe-mcp` | MCP server over stdio. |
| `supasafe-cli` | The `supasafe` binary. |

Every entry point (proxy, CLI, MCP, dashboard) calls the same
`Guard::evaluate`. There is exactly one place where "should this run?" is
decided, so the answer cannot drift between them.

## The decision path

1. **Split.** A character-level scanner splits the batch on top-level
   semicolons, understanding single quotes, dollar quotes, delimited
   identifiers and nested comments. This happens before parsing so that one
   unparseable statement cannot hide the ones around it.

2. **Parse.** Each statement goes through `sqlparser` with the PostgreSQL
   dialect. On success the analysis walks the AST: statement kind, every object
   and how it is accessed, `WHERE` clause analysis, and about thirty boolean
   flags (`cascade`, `drops_column`, `weakens_rls`, `copy_program`, and so on).

3. **Fall back.** When the grammar rejects a statement (`DO`, `REINDEX`,
   `CLUSTER`), a token-level classifier runs instead, over a tokenizer that
   understands quoting and comments. The result is marked `unparsed`, which the
   risk engine treats as an aggravating factor and the production policy
   refuses outright.

4. **Classify the environment.** Signals are gathered from configuration,
   Supabase project references, host names, database names and environment
   variables, each with a confidence. The highest confidence tier wins; within a
   tier the most severe environment wins. Nothing identified means production.

5. **Score.** A base score from the statement kind and shape, then modifiers.
   Every factor keeps its own description, so the number is always explainable.

6. **Measure.** Blast radius uses a catalogue snapshot when one is available:
   row counts from `pg_class.reltuples`, foreign keys from `pg_constraint`,
   cascade paths walked recursively with cycle protection. Without a catalogue
   it produces structural estimates and says so.

   The snapshot comes from a background task that connects with its own
   credentials every five minutes and runs three read-only queries. It uses a
   deliberately small PostgreSQL client, about four hundred lines: startup,
   authentication, simple query, text results. Enough to read `pg_class`, and no
   more surface than that needs. Authentication covers trust, cleartext, MD5 and
   SCRAM-SHA-256, and the SCRAM server proof is verified rather than ignored, so
   something that merely answers the handshake cannot impersonate the database.

7. **Decide.** Policy guards run first (protected surfaces, unparsed
   statements), then ordered rules where the first match wins, then the default
   escalated by score thresholds.

8. **Record.** A hash-chained audit record, then forward, refuse, or hold.

## Predicate analysis

The interesting part of the parser. `DELETE FROM users WHERE 1=1` has a `WHERE`
clause and deletes everything.

The analyser constant-folds the predicate to a boolean where it can. Only
literal-versus-literal comparisons fold: `id = 1` stays unknown because it
depends on the row, while `1 = 1`, `true`, `'a' = 'a'` and `NOT false` all fold
to true. A disjunction with a true branch is true, which catches
`WHERE email = 'x' OR 1=1`.

Separately it looks for a key equality: an `=` between a key-like column and a
constant or bind parameter, in a conjunction with no widening `OR`. That
produces four selectivity bands (`single_row`, `narrow`, `broad`, `unbounded`)
which drive both the score and the row estimate.

Without a catalogue, "key-like" is a heuristic over column names (`id`,
`*_id`, `uuid`). With one, it is the real primary key from `pg_index`.

## The session state machine

Two directions, one shared writer.

The backend-to-client task forwards everything verbatim and watches for
`ReadyForQuery` (transaction status), `CommandComplete` (row counts) and
`ErrorResponse` (what the database said). Those complete the audit records that
the frontend task queued when it forwarded a statement.

The frontend-to-backend task is where statements are judged. Two pieces of
state make refusals correct rather than merely loud:

- **`sink_until_sync`.** In the extended protocol, refusing a `Parse` means the
  client will still send `Bind`, `Execute` and `Describe` for a statement that
  was never parsed. Those are discarded until `Sync`, which is answered with a
  `ReadyForQuery`. This is what the server itself does after an error.

- **`aborted_by_us`.** Refusing inside an open transaction is the subtle case.
  The client is told the block is aborted, but the server never saw an error and
  believes its transaction is fine. Without handling, the client thinks its
  transaction failed while the server happily executes the rest of it. So
  SupaSafe emulates PostgreSQL exactly: every subsequent statement gets SQLSTATE
  `25P02` ("current transaction is aborted") until the client ends the block,
  and `COMMIT` is rewritten to `ROLLBACK` on the way out, because a `COMMIT` in
  an aborted transaction rolls back anyway.

There is an end-to-end test for that one: a batch of
`BEGIN; DROP TABLE t; INSERT INTO t VALUES (2); COMMIT;` must leave the table
untouched and the insert unapplied.

## Editing policy while it is running

`Guard` holds its configuration behind a lock, so a rule changed in the
dashboard applies to the next statement. Tuning a rule you cannot try out is
guesswork, and restarting a proxy to try one is how people stop trying.

Every edit runs against a copy of the configuration. The copy is compiled first,
and only a configuration that compiled is installed or written to disk. A rule
with a bad glob is a 400 and the running policy does not move.

The write itself prefers a temporary file and a rename. When that cannot work,
which is what happens when a single config file is bind-mounted into a container
and `rename` hits `EBUSY`, it falls back to writing in place and reports a
permission problem accurately rather than blaming the rename.

Two guards run before any rule and no rule can pass them: protected managed
surfaces, and unparseable statements. Turning either off is an explicit change
to `protect_managed_surfaces` or `deny_unparsed`, not something a rule can do
sideways.

## Threat model

**What SupaSafe defends against.** An AI agent with legitimate database
credentials that generates a statement more destructive than the person driving
it intended. That covers misunderstood context, a hallucinated table name, an
over-broad cleanup, a `WHERE` clause that does not filter, and prompt injection
that reaches the model through data it read.

**What it does not defend against.**

- An agent with a direct connection string. SupaSafe is in the path because you
  put it there. Give agents the proxy's address and nothing else.
- A malicious operator. Anyone who can edit `supasafe.toml` can allow anything,
  and anyone who can write the audit file can rewrite the whole chain. The
  dashboard's rule editor is the same authority in a browser, which is why it
  binds to loopback and can be switched off with `allow_policy_editing`.
- What a statement does once it is running. SupaSafe decides whether something
  executes, not what happens inside a function it approved.
- Anything that is not SQL. Direct filesystem access to the data directory,
  a compromised extension, or a stolen backup are all outside the path.

**Design choices that follow from the model.**

- *Fail closed.* An unidentified environment is production. An unparseable
  statement is refused. An unanswered approval is a refusal. A statement whose
  row count cannot be estimated is not assumed to be small.
- *No credentials.* Authentication is relayed rather than terminated, so
  compromising the proxy does not yield a database password.
- *No secrets in the trail.* Audit records store normalised SQL by default, and
  comments are dropped during normalisation because they carry whatever the
  model was told.
- *One decision point.* Every surface calls the same `Guard`, so a bypass in one
  is a bypass in all of them, and a fix in one fixes all of them.

## Performance

Analysis is a parse and a tree walk of one statement, on the order of tens of
microseconds. The proxy adds one hop. Nothing is buffered beyond a single
protocol message, and result sets stream through untouched.

The audit log is flushed on every append, which is deliberate: a record that was
never flushed is a record that did not happen.
