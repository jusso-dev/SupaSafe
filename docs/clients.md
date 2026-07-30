# Clients

SupaSafe speaks the PostgreSQL wire protocol, so any client works. Change the
connection string, change nothing else.

Start the proxy:

```sh
supasafe start --upstream "postgresql://postgres:...@db.abcdefgh.supabase.co:5432/postgres"
```

and give your agent the proxy instead:

```
postgresql://postgres:...@127.0.0.1:6432/postgres
```

The password is still your database password. SupaSafe relays authentication
without reading it.

## Set `application_name`

Not required, but worth thirty seconds. It is how the audit trail and the
approval card know which agent asked, and it is what `agents = [...]` matches on
in a policy rule.

```sh
export PGAPPNAME=claude-code
# or in the URL
postgresql://postgres:...@127.0.0.1:6432/postgres?application_name=claude-code
```

## Claude Code

`.env` or your shell:

```sh
export DATABASE_URL="postgresql://postgres:...@127.0.0.1:6432/postgres?application_name=claude-code"
```

Add the MCP server so Claude can check a statement before running it, and give
it the standing rules:

```sh
claude mcp add supasafe -- supasafe mcp --upstream "$DATABASE_URL"
supasafe context --target "$DATABASE_URL" >> CLAUDE.md
```

## Codex CLI

```sh
export DATABASE_URL="postgresql://postgres:...@127.0.0.1:6432/postgres?application_name=codex"
supasafe context --target "$DATABASE_URL" >> AGENTS.md
```

`~/.codex/config.toml`:

```toml
[mcp_servers.supasafe]
command = "supasafe"
args = ["mcp", "--upstream", "postgresql://postgres@127.0.0.1:6432/postgres"]
```

## Gemini CLI

`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "supasafe": {
      "command": "supasafe",
      "args": ["mcp", "--upstream", "postgresql://postgres@127.0.0.1:6432/postgres"]
    }
  }
}
```

## Cursor

Settings, or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "supasafe": {
      "command": "supasafe",
      "args": ["mcp", "--upstream", "postgresql://postgres@127.0.0.1:6432/postgres"]
    }
  }
}
```

Point any database extension at port 6432. Add the output of
`supasafe context` to `.cursorrules`.

## Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "supasafe": {
      "command": "supasafe",
      "args": ["mcp", "--upstream", "postgresql://postgres@127.0.0.1:6432/postgres"]
    }
  }
}
```

## Aider

```sh
export DATABASE_URL="postgresql://postgres:...@127.0.0.1:6432/postgres?application_name=aider"
supasafe context --target "$DATABASE_URL" >> CONVENTIONS.md
aider --read CONVENTIONS.md
```

## OpenCode

`opencode.json`:

```json
{
  "mcp": {
    "supasafe": {
      "type": "local",
      "command": ["supasafe", "mcp", "--upstream", "postgresql://postgres@127.0.0.1:6432/postgres"]
    }
  }
}
```

## Goose

`~/.config/goose/config.yaml`:

```yaml
extensions:
  supasafe:
    enabled: true
    type: stdio
    cmd: supasafe
    args: ["mcp", "--upstream", "postgresql://postgres@127.0.0.1:6432/postgres"]
```

## Hermes

Hermes reads MCP servers from `hermes.config.json`:

```json
{
  "mcpServers": {
    "supasafe": {
      "command": "supasafe",
      "args": ["mcp", "--upstream", "postgresql://postgres@127.0.0.1:6432/postgres"]
    }
  }
}
```

## psql

```sh
psql "postgresql://postgres@127.0.0.1:6432/postgres?application_name=manual"
```

Useful for watching SupaSafe work:

```
psql=> DELETE FROM users;
ERROR:  SupaSafe blocked this statement: it would delete every row from users
DETAIL:  This statement has no effective WHERE clause, so it rewrites or deletes every row in the table.
HINT:  Do not retry this in another form. Approve it in the SupaSafe dashboard, or write it as a reviewed migration.
```

## Application frameworks

Anything that takes a connection URL works, because nothing here is
SupaSafe-specific.

```js
// node-postgres, Prisma, Drizzle
DATABASE_URL="postgresql://postgres:...@127.0.0.1:6432/postgres?application_name=my-app"
```

```python
# psycopg, SQLAlchemy
DATABASE_URL = "postgresql://postgres:...@127.0.0.1:6432/postgres?application_name=my-app"
```

In practice you would run the proxy in front of agents rather than in front of
your application, but a staging deployment behind SupaSafe is a good way to find
out how much destructive SQL your codebase actually contains.

## Supabase CLI

`supabase db` commands connect directly and will not go through the proxy. Point
them at it explicitly when you want them covered:

```sh
supabase db push --db-url "postgresql://postgres:...@127.0.0.1:6432/postgres"
```

Reviewed migrations are the right way to change a production schema. SupaSafe is
for the ad hoc statements that were never reviewed by anyone.

## Verifying it is in the path

```sh
psql "postgresql://postgres@127.0.0.1:6432/postgres" -c "DELETE FROM some_table"
```

If that is refused, you are behind the proxy. If it runs, your client is still
connecting to the database directly, and the connection string it is actually
using is not the one you think it is.
