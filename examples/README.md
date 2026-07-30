# Examples

## Running it locally

The compose file is at the repository root, not here:

```sh
docker compose up --build
```

`docker/` holds what it uses: `seed.sql` builds the demo schema (8,412 signups,
20,000 orders, 60,000 order items, wired together with `ON DELETE CASCADE`) and
`supasafe.toml` is the configuration it starts from.

```sh
# allowed
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "SELECT count(*) FROM signups"

# held for approval, with a measured blast radius: 88,412 rows across three
# tables, two of which the statement does not mention
psql postgresql://postgres:postgres@127.0.0.1:6432/postgres -c "DELETE FROM signups"
```

Dashboard at http://127.0.0.1:7717, including the rule editor.

See [Running with Docker](../README.md#running-with-docker) for the full
description.

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
