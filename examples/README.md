# Examples

## `docker/` — try it without owning a production database

```sh
cd examples/docker
docker compose up
```

PostgreSQL with a seeded schema (8,412 signups, 20,000 orders, 60,000 order
items, wired together with `ON DELETE CASCADE`), and SupaSafe in front of it
declared as production. The database port is not published, so the only way in
is through the proxy. That is the arrangement you want in real life too.

```sh
# allowed
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "SELECT count(*) FROM signups"

# blocked, and the blast radius is measured rather than estimated,
# because the compose file gives SupaSafe a read-only introspection connection
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "DELETE FROM signups"
```

Dashboard at http://127.0.0.1:7717.

## `ci/` — check migrations in a pull request

`supasafe analyze` exits non-zero when a statement would be blocked, so it works
as a CI gate on the SQL in a diff. See `ci/check-migrations.sh` and
`ci/github-action.yml`.

## `configs/` — starting points

| File | For |
|---|---|
| `supabase-production.toml` | A hosted Supabase project with a read-only introspection role |
| `two-person.toml` | Regulated environments: two approvers, snapshot first |
| `team.toml` | A team with a shared staging database and per-agent rules |

Check any of them before using it:

```sh
supasafe --config examples/configs/team.toml doctor
supasafe --config examples/configs/team.toml policy production
```
