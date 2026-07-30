# SupaSafe for VS Code

Check SQL against your SupaSafe policy while you are writing it, and answer held
statements without leaving the editor.

The proxy is what actually stops a bad statement. This is the earlier warning:
it tells you the `DELETE` you just wrote has no usable `WHERE` clause while you
are still looking at it, rather than when an agent runs it at midnight.

## Requirements

SupaSafe running somewhere the editor can reach:

```sh
supasafe start --upstream "postgresql://postgres:...@db.abcdefgh.supabase.co/postgres"
```

The extension talks to the dashboard's HTTP API, so it reaches the same verdict
the proxy will.

## What it does

**Analyse a selection.** Select SQL, right-click, *SupaSafe: Analyze selection*.
A panel opens beside your file with the decision, the risk score and its
reasoning, the blast radius, and how to undo it.

**Warn on save.** Save a `.sql` file and anything scoring 25 or above appears in
the Problems panel. A statement that would be denied is an error; 80 and above
is a warning; the rest are informational. Turn it off with
`supasafe.analyzeOnSave`.

**Approve from the command palette.** *SupaSafe: Show statements awaiting
approval* lists what is held, with the agent, the target database and the SQL.
Approve it, reject it with a reason, or edit the SQL and approve that instead.

**Status bar.** A shield with a count when something is waiting. Click it to
answer.

## Settings

| Setting | Default | |
|---|---|---|
| `supasafe.serverUrl` | `http://127.0.0.1:7717` | The dashboard to talk to. |
| `supasafe.targetHost` | *(empty)* | Judge statements as if they were going to this host. Leave empty to use the detected environment. |
| `supasafe.analyzeOnSave` | `true` | Analyse `.sql` files on save. |
| `supasafe.approver` | *(empty)* | Name recorded against approvals you give. Prompted for if unset. |

Set `supasafe.targetHost` to your production host to see what a statement would
do there, even while you are working against a local database.

## Building

```sh
npm install
npm run compile
npm run package    # needs @vscode/vsce
```

## Notes

Approving from the editor writes to the audit trail exactly as approving from
the dashboard does, under the name in `supasafe.approver`. It is a
convenience, not an identity: SupaSafe records the name it was given.

If the dashboard is not running the extension stays quiet, shows
`SupaSafe: off` in the status bar, and clears its diagnostics. Editing a file
should not produce error notifications about a service you deliberately stopped.
