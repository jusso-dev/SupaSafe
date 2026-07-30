/**
 * SupaSafe for VS Code.
 *
 * The proxy is what actually stops a bad statement. This is the earlier
 * warning: it tells you the DELETE you just wrote has no usable WHERE clause
 * while you are still looking at it, rather than when an agent runs it.
 *
 * Everything goes through the same HTTP API the dashboard uses, so the verdict
 * here is the verdict the proxy will reach.
 */

import * as vscode from "vscode";
import * as http from "node:http";
import * as https from "node:https";
import { URL } from "node:url";

interface StatementVerdict {
  sql: string;
  kind: string;
  description: string;
  risk: { score: number; level: string };
  decision: string;
  rule: string | null;
  reasons: string[];
  objects: string[];
  blast: { summary: string; heaviest_lock: string; warnings: string[] };
  rollback: { reversibility: string; summary: string; steps: string[]; caveats: string[] };
}

interface Verdict {
  environment: string;
  environment_assumed: boolean;
  policy: string;
  decision: string;
  would_be_blocked: boolean;
  risk: number;
  message: string;
  statements: StatementVerdict[];
}

interface Approval {
  id: string;
  agent: string;
  sql: string;
  description: string;
  database: string;
  environment: string;
  risk: { score: number; level: string };
  approvals_required: number;
  state: { state: string };
  rollback: { reversibility: string };
}

let diagnostics: vscode.DiagnosticCollection;
let status: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("supasafe");
  context.subscriptions.push(diagnostics);

  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.command = "supasafe.showApprovals";
  context.subscriptions.push(status);
  void refreshStatus();

  const poll = setInterval(() => void refreshStatus(), 5000);
  context.subscriptions.push({ dispose: () => clearInterval(poll) });

  context.subscriptions.push(
    vscode.commands.registerCommand("supasafe.analyzeSelection", analyzeSelection),
    vscode.commands.registerCommand("supasafe.analyzeFile", analyzeFile),
    vscode.commands.registerCommand("supasafe.showApprovals", showApprovals),
    vscode.commands.registerCommand("supasafe.openDashboard", openDashboard),
    vscode.commands.registerCommand("supasafe.showContext", showContext),
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      if (document.languageId !== "sql") return;
      if (!config().get<boolean>("analyzeOnSave", true)) return;
      await lint(document);
    }),
    vscode.workspace.onDidCloseTextDocument((document) => diagnostics.delete(document.uri)),
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
  status?.dispose();
}

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("supasafe");
}

function serverUrl(): string {
  return config().get<string>("serverUrl", "http://127.0.0.1:7717").replace(/\/$/, "");
}

// --- talking to the dashboard ---------------------------------------------

function request(method: string, path: string, body?: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const url = new URL(serverUrl() + path);
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const transport = url.protocol === "https:" ? https : http;

    const req = transport.request(
      {
        method,
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        headers: {
          Accept: "application/json",
          ...(payload
            ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }
            : {}),
        },
        timeout: 5000,
      },
      (response) => {
        let text = "";
        response.on("data", (chunk) => (text += chunk));
        response.on("end", () => {
          let parsed: any = null;
          try {
            parsed = text ? JSON.parse(text) : null;
          } catch {
            reject(new Error("SupaSafe sent a response that was not JSON"));
            return;
          }
          const code = response.statusCode ?? 0;
          if (code >= 200 && code < 300) resolve(parsed);
          else reject(new Error(parsed?.error ?? `SupaSafe returned ${code}`));
        });
      },
    );

    req.on("timeout", () => req.destroy(new Error("SupaSafe did not respond")));
    req.on("error", (e) =>
      reject(
        new Error(
          `${e.message}. Is \`supasafe start\` running? Set supasafe.serverUrl if it is somewhere else.`,
        ),
      ),
    );
    if (payload) req.write(payload);
    req.end();
  });
}

async function analyze(sql: string): Promise<Verdict> {
  return request("POST", "/api/analyze", {
    sql,
    host: config().get<string>("targetHost", "") || undefined,
    agent: "vscode",
  });
}

// --- commands --------------------------------------------------------------

async function analyzeSelection(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  const sql = editor.document.getText(editor.selection) || editor.document.getText();
  if (!sql.trim()) {
    vscode.window.showInformationMessage("SupaSafe: nothing to analyse.");
    return;
  }
  await showVerdict(sql);
}

async function analyzeFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  await showVerdict(editor.document.getText());
  await lint(editor.document);
}

async function showVerdict(sql: string): Promise<void> {
  let verdict: Verdict;
  try {
    verdict = await analyze(sql);
  } catch (e) {
    vscode.window.showErrorMessage(`SupaSafe: ${(e as Error).message}`);
    return;
  }

  const panel = vscode.window.createWebviewPanel(
    "supasafe.verdict",
    "SupaSafe",
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );
  panel.webview.html = renderVerdict(verdict);
}

async function lint(document: vscode.TextDocument): Promise<void> {
  let verdict: Verdict;
  try {
    verdict = await analyze(document.getText());
  } catch {
    // A dashboard that is not running is not a reason to shout at somebody
    // who is just editing a file.
    diagnostics.delete(document.uri);
    return;
  }

  const found: vscode.Diagnostic[] = [];
  const text = document.getText();

  for (const statement of verdict.statements) {
    if (statement.risk.score < 25) continue;

    // Anchor on the statement's leading keyword. Failing that, the top of the
    // file, so the warning is never silently dropped.
    const keyword = statement.kind.split("_")[0].toUpperCase();
    const index = text.toUpperCase().indexOf(keyword);
    const start = index >= 0 ? document.positionAt(index) : new vscode.Position(0, 0);
    const end = index >= 0 ? document.positionAt(index + keyword.length) : new vscode.Position(0, 1);

    const severity =
      statement.decision === "deny"
        ? vscode.DiagnosticSeverity.Error
        : statement.risk.score >= 80
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Information;

    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(start, end),
      [
        `This would ${statement.description}.`,
        `Risk ${statement.risk.score} (${statement.risk.level}), ${statement.decision} under the ${verdict.policy} policy.`,
        ...statement.reasons,
      ].join(" "),
      severity,
    );
    diagnostic.source = "supasafe";
    diagnostic.code = statement.kind;
    found.push(diagnostic);
  }

  diagnostics.set(document.uri, found);
}

async function showApprovals(): Promise<void> {
  let approvals: Approval[];
  try {
    const body = await request("GET", "/api/approvals");
    approvals = (body.approvals as Approval[]).filter((a) => a.state.state === "pending");
  } catch (e) {
    vscode.window.showErrorMessage(`SupaSafe: ${(e as Error).message}`);
    return;
  }

  if (approvals.length === 0) {
    vscode.window.showInformationMessage("SupaSafe: nothing is waiting for approval.");
    return;
  }

  const picked = await vscode.window.showQuickPick(
    approvals.map((a) => ({
      label: `$(shield) risk ${a.risk.score}  ${a.description}`,
      description: `${a.agent} → ${a.database} (${a.environment})`,
      detail: a.sql,
      approval: a,
    })),
    { title: "Statements waiting for approval", matchOnDetail: true },
  );
  if (!picked) return;

  const action = await vscode.window.showQuickPick(
    [
      { label: "$(check) Approve", value: "approve" },
      { label: "$(x) Reject", value: "reject" },
      { label: "$(edit) Edit the SQL and approve that", value: "edit" },
      { label: "$(link-external) Open in the dashboard", value: "open" },
    ],
    { title: picked.approval.description },
  );
  if (!action) return;

  if (action.value === "open") {
    await openDashboard();
    return;
  }

  const approver =
    config().get<string>("approver") ||
    (await vscode.window.showInputBox({
      title: "Who is approving this?",
      prompt: "Recorded in the audit trail.",
    }));
  if (!approver) return;

  const body: Record<string, unknown> = { approver };

  if (action.value === "edit") {
    const sql = await vscode.window.showInputBox({
      title: "Statement to run instead",
      value: picked.approval.sql,
    });
    if (!sql) return;
    body.sql = sql;
  }

  if (action.value === "reject") {
    body.reason = await vscode.window.showInputBox({
      title: "Why is this being rejected?",
      prompt: "Optional, but the agent and the audit trail both see it.",
    });
  }

  try {
    await request("POST", `/api/approvals/${picked.approval.id}/${action.value}`, body);
    vscode.window.showInformationMessage(`SupaSafe: request ${action.value}ed.`);
    await refreshStatus();
  } catch (e) {
    vscode.window.showErrorMessage(`SupaSafe: ${(e as Error).message}`);
  }
}

async function openDashboard(): Promise<void> {
  await vscode.env.openExternal(vscode.Uri.parse(serverUrl()));
}

async function showContext(): Promise<void> {
  try {
    const body = await request("GET", "/api/policies");
    const document = await vscode.workspace.openTextDocument({
      language: "json",
      content: JSON.stringify(body, null, 2),
    });
    await vscode.window.showTextDocument(document, vscode.ViewColumn.Beside);
  } catch (e) {
    vscode.window.showErrorMessage(`SupaSafe: ${(e as Error).message}`);
  }
}

async function refreshStatus(): Promise<void> {
  try {
    const summary = await request("GET", "/api/summary");
    const pending = summary.pending_approvals as number;
    status.text = pending > 0 ? `$(shield) SupaSafe ${pending}` : "$(shield) SupaSafe";
    status.tooltip =
      pending > 0
        ? `${pending} statement(s) waiting for approval. Click to answer them.`
        : `SupaSafe is guarding. ${summary.statements} statement(s) seen, ${summary.blocked} blocked.`;
    status.backgroundColor =
      pending > 0 ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
    status.show();
  } catch {
    // Not running is a normal state, not an error worth a notification.
    status.text = "$(shield) SupaSafe: off";
    status.tooltip = "SupaSafe is not running. Start it with `supasafe start`.";
    status.backgroundColor = undefined;
    status.show();
  }
}

// --- rendering -------------------------------------------------------------

function escape(text: string): string {
  return String(text ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string,
  );
}

function renderVerdict(verdict: Verdict): string {
  const colour = (score: number) =>
    score >= 80 ? "var(--vscode-errorForeground)" : score >= 25 ? "var(--vscode-editorWarning-foreground)" : "var(--vscode-testing-iconPassed)";

  const statements = verdict.statements
    .map(
      (s) => `
      <div class="statement">
        <div class="head">
          <span class="risk" style="color:${colour(s.risk.score)}">RISK ${s.risk.score}</span>
          <span class="decision">${escape(s.decision)}</span>
        </div>
        <div class="desc">This would ${escape(s.description)}.</div>
        <pre>${escape(s.sql)}</pre>
        <ul>${s.reasons.map((r) => `<li>${escape(r)}</li>`).join("")}</ul>
        <div class="fact"><b>Blast radius</b> ${escape(s.blast.summary)}</div>
        <div class="fact"><b>Lock</b> ${escape(s.blast.heaviest_lock)}</div>
        <div class="fact"><b>Rollback</b> ${escape(s.rollback.summary)}</div>
        ${s.blast.warnings.map((w) => `<div class="warn">${escape(w)}</div>`).join("")}
        ${s.rollback.caveats.map((c) => `<div class="warn">${escape(c)}</div>`).join("")}
      </div>`,
    )
    .join("");

  return `<!doctype html>
<html><head><meta charset="utf-8"><style>
  body { font-family: var(--vscode-font-family); padding: 16px; color: var(--vscode-foreground); }
  .banner { padding: 12px 14px; border-radius: 6px; margin-bottom: 16px;
            background: var(--vscode-editorWidget-background);
            border-left: 3px solid ${verdict.would_be_blocked ? "var(--vscode-errorForeground)" : "var(--vscode-testing-iconPassed)"}; }
  .banner b { font-size: 15px; }
  .statement { border: 1px solid var(--vscode-widget-border); border-radius: 6px; padding: 14px; margin-bottom: 12px; }
  .head { display: flex; gap: 10px; align-items: baseline; margin-bottom: 8px; }
  .risk { font-weight: 700; font-family: var(--vscode-editor-font-family); }
  .decision { text-transform: uppercase; font-size: 11px; letter-spacing: .06em; opacity: .75; }
  .desc { font-weight: 600; margin-bottom: 8px; }
  pre { font-family: var(--vscode-editor-font-family); background: var(--vscode-textCodeBlock-background);
        padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }
  ul { padding-left: 18px; opacity: .85; }
  .fact { font-size: 13px; margin: 4px 0; opacity: .9; }
  .warn { font-size: 13px; margin: 4px 0; color: var(--vscode-editorWarning-foreground); }
</style></head>
<body>
  <div class="banner">
    <b>${verdict.would_be_blocked ? "This would be blocked." : "This would be allowed."}</b><br>
    ${escape(verdict.policy)} policy, ${escape(verdict.environment)}${verdict.environment_assumed ? " (assumed, nothing identified this database)" : ""}
  </div>
  ${statements}
</body></html>`;
}
