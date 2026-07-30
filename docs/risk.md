# Risk engine

Every statement gets a score from 0 to 100 and the list of factors that produced
it. The list matters as much as the number. A score nobody can explain is a score
nobody trusts, and an engineer staring at a blocked deploy at 2am needs to know
why in one screen.

Scores are independent of the environment. `DROP TABLE` is a 100 on a laptop and
a 100 in production. What changes is the policy that reads the score. Keeping the
two separate means the number means the same thing everywhere it appears.

## Bands

| Band | Range | What it means |
|---|---|---|
| `none` | 0 | Nothing changes. |
| `low` | 1-24 | Routine writes. |
| `moderate` | 25-49 | Worth noticing. |
| `high` | 50-79 | Wide-reaching. |
| `critical` | 80-94 | Destructive, recoverable only from a backup. |
| `catastrophic` | 95-100 | Irreversible loss of data or control. |

## Base scores

From the statement kind and shape, before modifiers.

**Reads.** `SELECT`, `EXPLAIN`, `SHOW`, `FETCH`, `COPY ... TO`: **0**.

**Writes.**

| | |
|---|---|
| `INSERT` | 15 |
| `MERGE` | 55 |
| `COPY ... FROM` | 30 |

`UPDATE` and `DELETE` depend on how much of the table they can reach:

| Selectivity | `UPDATE` | `DELETE` |
|---|---|---|
| `single_row` (key equality) | 10 | 20 |
| `narrow` (bounded set, `IN` list, `LIMIT`) | 25 | 35 |
| `broad` (filters something, unbounded fraction) | 60 | 70 |
| `unbounded` (no `WHERE`, or a tautological one) | 98 | 100 |

`TRUNCATE`: **95**. It empties the table without per-row WAL, so it cannot be
undone by replaying the log or caught by a row trigger. With `CASCADE` the
modifier takes it to 100.

**Destructive DDL.**

| | |
|---|---|
| `DROP DATABASE`, `DROP SCHEMA`, `DROP TABLE` | 100 |
| `ALTER TABLE ... DROP COLUMN` | 98 |
| `DROP POLICY` | 90 |
| `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` | 85 base, floored at 90 by a modifier |
| `ALTER ... OWNER TO` | 75 |
| `DROP SEQUENCE`, `DROP EXTENSION`, `DROP ROLE` | 70 |
| `DROP TRIGGER` | 65 |
| `ALTER TABLE ... ALTER COLUMN TYPE` | 70 |
| `ALTER TABLE ... DROP CONSTRAINT` | 65 |
| rename | 60 |
| `DROP VIEW`, `DROP INDEX` | 55 |

**Additive DDL.** `CREATE TABLE`, `CREATE INDEX`, `CREATE VIEW`, `CREATE POLICY`
and friends: **15**. Functions, procedures and triggers: **25**.
`CREATE EXTENSION`: **45**, because it loads code into the server.
`CREATE ROLE`: **50**.

**Permissions.** `GRANT` 55, `REVOKE` 45.

**Maintenance.** `VACUUM`, `ANALYZE` 10. `REINDEX`, `CLUSTER` 45.

**Execution.** `CALL`, `EXECUTE` 45. `DO` 55.

**Transaction and session control.** 0 to 5. `LOCK TABLE` is 35.

**Unknown.** A statement SupaSafe cannot classify: **70**. Not zero. Not 100
either, because "I do not know" is not the same as "this is a disaster", and the
policy is what refuses it.

## Modifiers

Applied on top. Some add points; some set a floor the total cannot fall below.

| Factor | Effect | Why |
|---|---|---|
| `protected_surface` | floor 100 if lossy, else 90 | Writing to Supabase's `auth`, `storage`, `vault` or `supabase_migrations`, or to a PostgreSQL catalog. |
| `command_execution` | floor 100 | `COPY ... PROGRAM` is remote code execution on the database host. |
| `privilege_escalation` | floor 95 | `SUPERUSER`, `BYPASSRLS`, `REPLICATION` remove every other boundary, including SupaSafe. |
| `weakens_rls` | floor 90 | On Supabase this exposes the table to the anon key. |
| `hidden_destruction` | floor 85 | An opaque body containing `DROP`, `DELETE`, `TRUNCATE`. |
| `grant_all_public` | floor 85 | `GRANT ALL` to `PUBLIC`, `anon` or `authenticated`. |
| `unparsed` | +25 | Classified from tokens, not verified against a grammar. |
| `security_definer` | +20 | Runs with the owner's rights and bypasses RLS for the caller. |
| `cascade` | +10 | Reaches objects the statement does not name. |
| `ownership_change` | +15 | Transfers control. |
| `disables_trigger` | +15 | Turns off integrity or audit logic, invisibly. |
| `server_filesystem` | +15 | `COPY` to or from a path on the server. |
| `blocking_index_build` | +15 | `CREATE INDEX` without `CONCURRENTLY`. |
| `table_rewrite` | +10 | A column type change rewrites the table under a lock. |
| `opaque_body` | +10 | A body static analysis cannot see into. |
| `multi_table` | +5 | A write across more than one table. |
| `row_volume` | -5 to +20 | Scaled by the estimated row count, from "no rows" to "over a million". |
| `in_transaction` | -5 | The client can still `ROLLBACK`. Real, but small: nothing stops it committing. |
| `explicit_limit` | -10 | A `LIMIT` bounds what a write can touch. |
| `no_op` | -40 | The `WHERE` clause can never be true. |

Floors are taken as the maximum of every floor that applies, then the total is
`max(sum, floor)` clamped to 0-100.

## Why `WHERE 1=1` scores 100

The predicate is constant-folded. Only literal-versus-literal comparisons fold,
so `id = 1` stays unknown (it depends on the row) while these do not:

```sql
WHERE 1=1                      -- true
WHERE true                     -- true
WHERE 'a' = 'a'                -- true
WHERE 2 > 1                    -- true
WHERE NOT false                -- true
WHERE TRUE AND 1 = 1           -- true
WHERE email = 'x' OR 1=1       -- true: a disjunction with a true branch
WHERE 1 = 2                    -- false, and scored as a no-op
```

A predicate that folds to true is treated identically to no `WHERE` clause at
all, because that is what it is.

## Reading a score

```sh
$ supasafe analyze "DROP TABLE public.users CASCADE" --environment production --json
```

```json
{
  "risk": 100,
  "statements": [{
    "risk": {
      "score": 100,
      "level": "catastrophic",
      "base": 100,
      "factors": [
        {
          "code": "drop_table",
          "description": "DROP TABLE destroys the table and all of its data; PostgreSQL keeps no copy",
          "delta": 0
        },
        {
          "code": "cascade",
          "description": "CASCADE extends this change to dependent objects the statement does not name",
          "delta": 10
        }
      ]
    }
  }]
}
```

## Stability

The scores in this document are covered by tests in
`crates/supasafe-core/src/risk.rs`. They are the contract: if one changes, the
change is deliberate and documented, not a side effect.
