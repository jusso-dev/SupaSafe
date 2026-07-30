//! The dashboard, served as one self-contained page.
//!
//! No build step, no bundler, no CDN. A security tool that pulls JavaScript
//! from a third party at runtime has undone a good part of its own argument,
//! and a dashboard that needs `npm install` before it will show you a blocked
//! query is a dashboard nobody opens during an incident.

use axum::response::Html;

pub async fn index() -> Html<&'static str> {
    Html(PAGE)
}

const PAGE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SupaSafe</title>
<style>
  :root {
    --bg: #0b0f14;
    --panel: #121822;
    --panel-2: #172030;
    --line: #223047;
    --text: #e6edf6;
    --muted: #8595ad;
    --green: #3ddc97;
    --amber: #ffc857;
    --red: #ff5d5d;
    --violet: #a78bfa;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #f6f8fb; --panel: #ffffff; --panel-2: #f0f4f9; --line: #dce4ee;
      --text: #101725; --muted: #5c6b82;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  header {
    display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
    padding: 18px 24px; border-bottom: 1px solid var(--line); background: var(--panel);
    position: sticky; top: 0; z-index: 10;
  }
  .brand { font-weight: 650; font-size: 17px; letter-spacing: -0.01em; }
  .brand span { color: var(--green); }
  .spacer { flex: 1; }
  .pill {
    font: 12px/1 var(--mono); padding: 6px 10px; border-radius: 999px;
    border: 1px solid var(--line); color: var(--muted); background: var(--panel-2);
  }
  .pill.good { color: var(--green); border-color: color-mix(in srgb, var(--green) 40%, var(--line)); }
  .pill.bad { color: var(--red); border-color: color-mix(in srgb, var(--red) 40%, var(--line)); }
  main { padding: 24px; max-width: 1200px; margin: 0 auto; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin: 32px 0 12px; font-weight: 600; }
  h2:first-child { margin-top: 0; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px; }
  .card .n { font: 600 28px/1.1 var(--mono); letter-spacing: -0.02em; }
  .card .l { color: var(--muted); font-size: 12px; margin-top: 6px; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
  .empty { padding: 28px; color: var(--muted); text-align: center; font-size: 14px; }
  .approval { border-bottom: 1px solid var(--line); padding: 18px 20px; }
  .approval:last-child { border-bottom: 0; }
  .approval .top { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
  .agent { font: 12px/1 var(--mono); color: var(--violet); }
  .when { color: var(--muted); font-size: 12px; }
  .desc { font-weight: 600; margin-bottom: 10px; }
  pre.sql {
    font: 13px/1.5 var(--mono); background: var(--panel-2); border: 1px solid var(--line);
    border-radius: 8px; padding: 12px 14px; overflow-x: auto; margin: 0 0 12px;
    white-space: pre-wrap; word-break: break-word;
  }
  .facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-bottom: 12px; }
  .fact { background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
  .fact .k { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
  .fact .v { font: 13px/1.4 var(--mono); margin-top: 4px; word-break: break-word; }
  ul.reasons { margin: 0 0 12px; padding-left: 18px; color: var(--muted); font-size: 13px; }
  ul.reasons li { margin: 3px 0; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
  button {
    font: 500 13px/1 inherit; padding: 9px 14px; border-radius: 8px; cursor: pointer;
    border: 1px solid var(--line); background: var(--panel-2); color: var(--text);
  }
  button:hover { border-color: var(--muted); }
  button.approve { background: color-mix(in srgb, var(--green) 18%, transparent); border-color: var(--green); color: var(--green); }
  button.reject { background: color-mix(in srgb, var(--red) 15%, transparent); border-color: var(--red); color: var(--red); }
  input[type=text] {
    font: 13px/1 var(--mono); padding: 9px 11px; border-radius: 8px; flex: 1; min-width: 120px;
    border: 1px solid var(--line); background: var(--bg); color: var(--text);
  }
  .risk { font: 600 12px/1 var(--mono); padding: 5px 9px; border-radius: 6px; }
  .risk.none, .risk.low { background: color-mix(in srgb, var(--green) 16%, transparent); color: var(--green); }
  .risk.moderate { background: color-mix(in srgb, var(--amber) 16%, transparent); color: var(--amber); }
  .risk.high { background: color-mix(in srgb, var(--amber) 22%, transparent); color: var(--amber); }
  .risk.critical, .risk.catastrophic { background: color-mix(in srgb, var(--red) 18%, transparent); color: var(--red); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--line); font-size: 13px; }
  th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
  td.sql { font: 12px/1.4 var(--mono); color: var(--muted); max-width: 460px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  tr:last-child td { border-bottom: 0; }
  .decision { font: 600 11px/1 var(--mono); text-transform: uppercase; letter-spacing: 0.04em; }
  .decision.allow { color: var(--green); }
  .decision.warn { color: var(--amber); }
  .decision.require_approval { color: var(--violet); }
  .decision.deny { color: var(--red); }
  .timeline { display: block; width: 100%; height: 90px; }
  .scroll { overflow-x: auto; }
  .check { display: flex; gap: 8px; padding: 16px 20px; }

  /* --- rule editor --- */
  select, textarea {
    font: 13px/1.4 inherit; padding: 8px 10px; border-radius: 8px;
    border: 1px solid var(--line); background: var(--bg); color: var(--text);
  }
  select[multiple] { padding: 4px; }
  textarea { width: 100%; min-height: 46vh; font-family: var(--mono); font-size: 12.5px; resize: vertical; }
  button.primary { background: color-mix(in srgb, var(--green) 18%, transparent); border-color: var(--green); color: var(--green); }
  button.ghost { background: transparent; }
  button.tiny { padding: 5px 8px; font-size: 12px; }
  button:disabled { opacity: .45; cursor: not-allowed; }
  .hint { color: var(--muted); font-size: 12px; }
  .err { color: var(--red); font-size: 12.5px; }
  .rules-bar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; padding: 14px 18px; border-bottom: 1px solid var(--line); }
  .rules-foot { display: flex; gap: 10px; align-items: center; padding: 14px 18px; border-top: 1px solid var(--line); }
  .settings { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
              gap: 10px; padding: 14px 18px; border-bottom: 1px solid var(--line); }
  .setting { background: var(--panel-2); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
  .setting label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-bottom: 6px; }
  .setting input, .setting select { width: 100%; font: 13px/1 var(--mono); padding: 6px 8px; }
  .rule { display: flex; gap: 12px; align-items: flex-start; padding: 12px 18px; border-bottom: 1px solid var(--line); }
  .rule:last-child { border-bottom: 0; }
  .rule .ord { font: 600 12px/1.6 var(--mono); color: var(--muted); min-width: 22px; }
  .rule .body { flex: 1; min-width: 0; }
  .rule .title { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
  .rule .title b { font-size: 13.5px; }
  .rule .when { font: 12px/1.5 var(--mono); color: var(--muted); margin-top: 3px; word-break: break-word; }
  .rule .msg { font-size: 12.5px; color: var(--muted); margin-top: 3px; }
  .rule .tools { display: flex; gap: 4px; }
  .act { font: 600 11px/1 var(--mono); text-transform: uppercase; letter-spacing: .04em; padding: 4px 7px; border-radius: 5px; }
  .act.allow { background: color-mix(in srgb, var(--green) 16%, transparent); color: var(--green); }
  .act.warn { background: color-mix(in srgb, var(--amber) 16%, transparent); color: var(--amber); }
  .act.require_approval { background: color-mix(in srgb, var(--violet) 18%, transparent); color: var(--violet); }
  .act.deny { background: color-mix(in srgb, var(--red) 16%, transparent); color: var(--red); }
  .modal { position: fixed; inset: 0; background: rgba(0,0,0,.55); display: flex;
           align-items: center; justify-content: center; padding: 24px; z-index: 50; }
  .modal[hidden] { display: none; }
  .sheet { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
           width: min(820px, 100%); max-height: 92vh; display: flex; flex-direction: column; }
  .sheet-head, .sheet-foot { display: flex; gap: 10px; align-items: center; padding: 14px 18px; }
  .sheet-head { border-bottom: 1px solid var(--line); }
  .sheet-foot { border-top: 1px solid var(--line); }
  .sheet-body { padding: 16px 18px; overflow-y: auto; }
  .field { margin-bottom: 14px; }
  .field > label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-bottom: 6px; }
  .field input[type=text], .field input[type=number], .field select { width: 100%; }
  .row { display: flex; gap: 8px; align-items: center; }
  .grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; }
  .grid3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; }
  .sep { font-size: 12px; color: var(--muted); margin: 18px 0 12px; padding-top: 12px; border-top: 1px solid var(--line); }
  footer { color: var(--muted); font-size: 12px; padding: 32px 24px; text-align: center; }
  footer code { font-family: var(--mono); }
</style>
</head>
<body>
<header>
  <div class="brand">Supa<span>Safe</span></div>
  <div class="pill" id="env">loading…</div>
  <div class="spacer"></div>
  <div class="pill" id="audit-state">audit …</div>
  <div class="pill" id="version"></div>
</header>

<main>
  <h2>Now</h2>
  <div class="cards" id="cards"></div>

  <h2>Risk over the last 100 statements</h2>
  <div class="panel"><svg class="timeline" id="timeline" preserveAspectRatio="none"></svg></div>

  <h2>Waiting for you</h2>
  <div class="panel" id="approvals"><div class="empty">Nothing is waiting. Agents are working within policy.</div></div>

  <h2>What would happen if…</h2>
  <div class="panel">
    <div class="check">
      <input type="text" id="try-sql" placeholder="DROP TABLE users" spellcheck="false">
      <button id="try-go">Check</button>
    </div>
    <div id="try-out"></div>
  </div>

  <h2>Rules the proxy enforces</h2>
  <div class="panel" id="rules-panel">
    <div class="rules-bar">
      <select id="policy-select"></select>
      <span class="hint" id="policy-desc"></span>
      <span class="spacer"></span>
      <span class="hint" id="policy-file"></span>
      <button id="policy-reload" title="Re-read supasafe.toml from disk">Reload file</button>
      <button id="policy-raw">Edit as TOML</button>
    </div>
    <div id="policy-settings" class="settings"></div>
    <div id="rules-list"></div>
    <div class="rules-foot">
      <button id="rule-add" class="primary">Add a rule</button>
      <span class="hint">The first rule that matches decides. New rules go to the top.</span>
    </div>
  </div>

  <h2>Recent statements</h2>
  <div class="panel scroll" id="audit"><div class="empty">No statements yet.</div></div>
</main>

<!-- Rule editor -->
<div class="modal" id="rule-modal" hidden>
  <div class="sheet">
    <div class="sheet-head">
      <b id="rule-modal-title">Add a rule</b>
      <button id="rule-close" class="ghost">Close</button>
    </div>
    <div class="sheet-body">
      <div class="field">
        <label for="rule-name">Name</label>
        <input type="text" id="rule-name" placeholder="billing-is-off-limits" spellcheck="false">
        <div class="hint">Appears in the block message and the audit trail.</div>
      </div>

      <div class="field">
        <label for="rule-action">Then</label>
        <div class="row">
          <select id="rule-action"></select>
          <input type="number" id="rule-approvals" min="1" max="9" placeholder="approvals" style="max-width:120px">
        </div>
      </div>

      <div class="field">
        <label for="rule-message">Message</label>
        <input type="text" id="rule-message" placeholder="Why this rule exists, in plain language.">
        <div class="hint">Shown to the human and returned to the agent. Worth writing properly.</div>
      </div>

      <div class="sep">Match when <b>all</b> of these hold. Leave a field empty to ignore it.</div>

      <div class="grid2">
        <div class="field">
          <label for="rule-kinds">Statement kinds</label>
          <select id="rule-kinds" multiple size="7"></select>
        </div>
        <div class="field">
          <label for="rule-categories">Categories</label>
          <select id="rule-categories" multiple size="7"></select>
        </div>
      </div>

      <div class="grid2">
        <div class="field">
          <label for="rule-objects">Objects</label>
          <input type="text" id="rule-objects" placeholder="billing.*, public.audit_*" spellcheck="false">
          <div class="hint">Globs against schema.object, comma separated.</div>
        </div>
        <div class="field">
          <label for="rule-agents">Agents</label>
          <input type="text" id="rule-agents" placeholder="claude-*, migration-runner" spellcheck="false">
          <div class="hint">Globs against application_name. Not authentication.</div>
        </div>
      </div>

      <div class="grid2">
        <div class="field">
          <label for="rule-any-flags">Any of these flags</label>
          <select id="rule-any-flags" multiple size="6"></select>
        </div>
        <div class="field">
          <label for="rule-flags">All of these flags</label>
          <select id="rule-flags" multiple size="6"></select>
        </div>
      </div>

      <div class="grid3">
        <div class="field">
          <label for="rule-unfiltered">Row filter</label>
          <select id="rule-unfiltered">
            <option value="">any</option>
            <option value="true">no effective WHERE</option>
            <option value="false">has a real WHERE</option>
          </select>
        </div>
        <div class="field">
          <label for="rule-min-risk">Risk at least</label>
          <input type="number" id="rule-min-risk" min="0" max="100" placeholder="0">
        </div>
        <div class="field">
          <label for="rule-max-risk">Risk at most</label>
          <input type="number" id="rule-max-risk" min="0" max="100" placeholder="100">
        </div>
      </div>

      <div class="field">
        <label for="rule-environments">Environments</label>
        <select id="rule-environments" multiple size="4"></select>
      </div>

      <div class="sep">Try it before you save it</div>
      <div class="field">
        <div class="row">
          <input type="text" id="rule-test-sql" placeholder="DELETE FROM billing.invoices WHERE id = 1" spellcheck="false">
          <button id="rule-test">Test</button>
        </div>
        <div id="rule-test-out"></div>
      </div>
    </div>
    <div class="sheet-foot">
      <span class="err" id="rule-error"></span>
      <span class="spacer"></span>
      <button id="rule-cancel" class="ghost">Cancel</button>
      <button id="rule-save" class="primary">Save rule</button>
    </div>
  </div>
</div>

<!-- Raw TOML editor -->
<div class="modal" id="toml-modal" hidden>
  <div class="sheet">
    <div class="sheet-head">
      <b>supasafe.toml</b>
      <button id="toml-close" class="ghost">Close</button>
    </div>
    <div class="sheet-body">
      <textarea id="toml-text" spellcheck="false"></textarea>
      <div class="hint">
        Parsed and compiled before anything is saved. A mistake here is an error message,
        not a proxy that has forgotten its policies.
      </div>
    </div>
    <div class="sheet-foot">
      <span class="err" id="toml-error"></span>
      <span class="spacer"></span>
      <button id="toml-cancel" class="ghost">Cancel</button>
      <button id="toml-save" class="primary">Save and apply</button>
    </div>
  </div>
</div>

<footer>
  Every decision on this page is recorded in a hash-chained audit log.
  Verify it with <code>supasafe audit --verify</code>.
</footer>

<script>
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]
));
const band = (n) => n === 0 ? "none" : n < 25 ? "low" : n < 50 ? "moderate"
  : n < 80 ? "high" : n < 95 ? "critical" : "catastrophic";

async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || response.statusText);
  return body;
}

async function loadSummary() {
  const s = await api("/api/summary");
  $("version").textContent = "v" + s.version;
  $("audit-state").textContent = s.audit_intact ? "audit chain intact" : "AUDIT CHAIN BROKEN";
  $("audit-state").className = "pill " + (s.audit_intact ? "good" : "bad");
  $("env").textContent = s.policies.join(" · ") + (s.has_catalog ? " · live catalog" : " · static estimates");

  $("cards").innerHTML = [
    [s.statements, "statements seen"],
    [s.blocked, "blocked"],
    [s.executed, "executed"],
    [s.pending_approvals, "awaiting approval"],
    [s.highest_risk, "highest risk"],
  ].map(([n, l]) => `<div class="card"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");

  drawTimeline(s.timeline || []);
}

function drawTimeline(points) {
  const svg = $("timeline");
  const w = svg.clientWidth || 900, h = 90, pad = 6;
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  if (!points.length) {
    svg.innerHTML = `<text x="${w/2}" y="${h/2}" fill="#8595ad" font-size="12" text-anchor="middle">no statements yet</text>`;
    return;
  }
  const step = points.length > 1 ? (w - pad * 2) / (points.length - 1) : 0;
  const y = (risk) => h - pad - (risk / 100) * (h - pad * 2);
  const colour = (risk) => risk >= 95 ? "#ff5d5d" : risk >= 80 ? "#ff5d5d"
    : risk >= 50 ? "#ffc857" : risk >= 25 ? "#ffc857" : "#3ddc97";

  const line = points.map((p, i) => `${i === 0 ? "M" : "L"}${pad + i * step},${y(p.risk)}`).join(" ");
  const dots = points.map((p, i) =>
    `<circle cx="${pad + i * step}" cy="${y(p.risk)}" r="2.5" fill="${colour(p.risk)}">
       <title>${esc(p.kind)} — risk ${p.risk} — ${esc(p.decision)}</title></circle>`).join("");

  svg.innerHTML =
    `<line x1="0" y1="${y(80)}" x2="${w}" y2="${y(80)}" stroke="#ff5d5d" stroke-dasharray="3 4" opacity="0.35"/>
     <path d="${line}" fill="none" stroke="#8595ad" stroke-width="1.2" opacity="0.6"/>${dots}`;
}

function factsFor(a) {
  const b = a.blast || {};
  return [
    ["risk", `${a.risk.score} (${a.risk.level})`],
    ["rows affected", (b.rows_affected && b.rows_affected.value != null) ? b.rows_affected.value : "unknown"],
    ["objects", (a.affected_objects || []).join(", ") || "—"],
    ["lock", b.heaviest_lock || "—"],
    ["environment", a.environment],
    ["reversible", a.rollback ? a.rollback.reversibility.replace("_", " ") : "—"],
    ["recovery point", a.recovery_point || "none taken"],
    ["approvals needed", a.approvals_required],
  ].map(([k, v]) => `<div class="fact"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join("");
}

function renderApprovals(list) {
  const pending = list.filter(a => a.state.state === "pending");
  const el = $("approvals");
  if (!pending.length) {
    el.innerHTML = `<div class="empty">Nothing is waiting. Agents are working within policy.</div>`;
    return;
  }
  el.innerHTML = pending.map(a => `
    <div class="approval" data-id="${esc(a.id)}">
      <div class="top">
        <span class="risk ${band(a.risk.score)}">RISK ${a.risk.score}</span>
        <span class="agent">${esc(a.agent)}</span>
        <span class="when">wants to run this against ${esc(a.database)} (${esc(a.environment)})</span>
      </div>
      <div class="desc">This would ${esc(a.description)}.</div>
      <pre class="sql">${esc(a.sql)}</pre>
      <div class="facts">${factsFor(a)}</div>
      ${(a.policy_reasons || []).length ? `<ul class="reasons">${a.policy_reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
      ${(a.blast && a.blast.warnings || []).length ? `<ul class="reasons">${a.blast.warnings.map(r => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
      ${(a.rollback && a.rollback.caveats || []).length ? `<ul class="reasons">${a.rollback.caveats.map(r => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
      <div class="actions">
        <input type="text" class="who" placeholder="your name" value="${esc(localStorage.getItem("supasafe-approver") || "")}">
        <button class="approve">Approve</button>
        <button class="reject">Reject</button>
        <button class="edit">Approve edited SQL…</button>
      </div>
    </div>`).join("");
}

async function decide(id, action, row) {
  const approver = row.querySelector(".who").value.trim();
  if (!approver) { row.querySelector(".who").focus(); return; }
  localStorage.setItem("supasafe-approver", approver);

  const body = { approver };
  if (action === "edit") {
    const sql = prompt("Statement to run instead:", row.querySelector(".sql").textContent);
    if (!sql) return;
    body.sql = sql;
  }
  if (action === "reject") {
    body.reason = prompt("Why? (optional)") || null;
  }
  try {
    await api(`/api/approvals/${id}/${action}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    await refresh();
  } catch (e) {
    alert(e.message);
  }
}

$("approvals").addEventListener("click", (event) => {
  const row = event.target.closest(".approval");
  if (!row) return;
  for (const action of ["approve", "reject", "edit"]) {
    if (event.target.classList.contains(action)) decide(row.dataset.id, action, row);
  }
});

async function loadAudit() {
  const { records } = await api("/api/audit?limit=60");
  const el = $("audit");
  if (!records.length) { el.innerHTML = `<div class="empty">No statements yet.</div>`; return; }
  el.innerHTML = `<table>
    <thead><tr><th>time</th><th>agent</th><th>statement</th><th>risk</th><th>decision</th><th>outcome</th></tr></thead>
    <tbody>${records.map(r => `
      <tr>
        <td>${esc(new Date(r.timestamp).toLocaleTimeString())}</td>
        <td class="sql">${esc(r.agent)}</td>
        <td class="sql" title="${esc(r.sql)}">${esc(r.sql)}</td>
        <td><span class="risk ${band(r.risk)}">${r.risk}</span></td>
        <td><span class="decision ${esc(r.decision.action)}">${esc(r.decision.action)}</span></td>
        <td>${esc(r.outcome.outcome ?? r.outcome)}</td>
      </tr>`).join("")}</tbody></table>`;
}

$("try-go").addEventListener("click", async () => {
  const sql = $("try-sql").value.trim();
  if (!sql) return;
  const out = $("try-out");
  try {
    const v = await api("/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sql, host: "db.example.supabase.co", agent: "dashboard" }),
    });
    out.innerHTML = v.statements.map(s => `
      <div class="approval">
        <div class="top">
          <span class="risk ${band(s.risk.score)}">RISK ${s.risk.score}</span>
          <span class="decision ${esc(s.decision)}">${esc(s.decision)}</span>
          <span class="when">under the ${esc(v.policy)} policy in ${esc(v.environment)}</span>
        </div>
        <div class="desc">This would ${esc(s.description)}.</div>
        <ul class="reasons">${s.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul>
        <div class="facts">
          <div class="fact"><div class="k">blast radius</div><div class="v">${esc(s.blast.summary)}</div></div>
          <div class="fact"><div class="k">lock</div><div class="v">${esc(s.blast.heaviest_lock)}</div></div>
          <div class="fact"><div class="k">reversible</div><div class="v">${esc(s.rollback.reversibility.replace("_", " "))}</div></div>
        </div>
      </div>`).join("");
  } catch (e) {
    out.innerHTML = `<div class="empty">${esc(e.message)}</div>`;
  }
});
$("try-sql").addEventListener("keydown", (e) => { if (e.key === "Enter") $("try-go").click(); });

// ---------------------------------------------------------------------------
// Rule editing
//
// The rules on this page are the ones the proxy is enforcing right now. Saving
// one applies it to the next statement and writes it to supasafe.toml, so what
// you see here and what is on disk do not drift apart.
// ---------------------------------------------------------------------------

let vocab = null;
let policies = [];
let editable = false;
let currentPolicy = null;
let editingIndex = null;   // null when adding

const SETTINGS = [
  ["default", "default action", "select", ["allow", "warn", "require_approval", "deny"]],
  ["warn_above", "warn above", "number"],
  ["require_approval_above", "approval above", "number"],
  ["deny_above", "refuse above", "number"],
  ["approvals_required", "approvers needed", "number"],
  ["snapshot_above", "snapshot above", "number"],
  ["approval_timeout_seconds", "approval expires (s)", "number"],
  ["protect_managed_surfaces", "protect auth/storage", "bool"],
  ["deny_unparsed", "refuse unparseable SQL", "bool"],
];

async function loadPolicies() {
  if (!vocab) vocab = await api("/api/policies/vocabulary");
  const body = await api("/api/policies");
  policies = body.policies;
  editable = body.editable;

  const select = $("policy-select");
  const keep = currentPolicy || select.value || "production";
  select.innerHTML = policies.map(p => `<option value="${esc(p.name)}">${esc(p.name)}</option>`).join("");
  select.value = policies.some(p => p.name === keep) ? keep : policies[0]?.name;
  currentPolicy = select.value;

  $("policy-file").textContent = body.config_path
    ? (editable ? `saving to ${body.config_path}` : `read only: ${body.config_path}`)
    : "no config file: changes would not survive a restart";

  renderPolicy();
}

function policyByName(name) {
  return policies.find(p => p.name === name);
}

function renderPolicy() {
  const p = policyByName(currentPolicy);
  if (!p) return;
  $("policy-desc").textContent = p.description;

  $("policy-settings").innerHTML = SETTINGS.map(([key, label, type, options]) => {
    const value = p[key];
    if (type === "bool") {
      return `<div class="setting"><label>${esc(label)}</label>
        <select data-setting="${key}" ${editable ? "" : "disabled"}>
          <option value="true" ${value ? "selected" : ""}>yes</option>
          <option value="false" ${value ? "" : "selected"}>no</option>
        </select></div>`;
    }
    if (type === "select") {
      return `<div class="setting"><label>${esc(label)}</label>
        <select data-setting="${key}" ${editable ? "" : "disabled"}>
          ${options.map(o => `<option ${o === value ? "selected" : ""}>${esc(o)}</option>`).join("")}
        </select></div>`;
    }
    return `<div class="setting"><label>${esc(label)}</label>
      <input type="number" min="0" max="100000" data-setting="${key}"
             value="${value === null || value === undefined ? "" : value}"
             placeholder="off" ${editable ? "" : "disabled"}></div>`;
  }).join("");

  $("rules-list").innerHTML = p.rules.length
    ? p.rules.map(r => renderRule(r, p.rules.length)).join("")
    : `<div class="empty">No rules. The default action and the thresholds decide everything.</div>`;

  $("rule-add").disabled = !editable;
}

function describeWhen(when) {
  const parts = [];
  const list = (k, label) => {
    if (when[k] && when[k].length) parts.push(`${label}: ${when[k].join(", ")}`);
  };
  list("kinds", "kinds");
  list("categories", "categories");
  list("objects", "objects");
  list("schemas", "schemas");
  list("surfaces", "surfaces");
  list("flags", "all flags");
  list("any_flags", "any flag");
  list("environments", "environments");
  list("agents", "agents");
  if (when.unfiltered === true) parts.push("no effective WHERE");
  if (when.unfiltered === false) parts.push("has a real WHERE");
  if (when.unparsed === true) parts.push("unparseable");
  if (when.min_risk !== null && when.min_risk !== undefined) parts.push(`risk ≥ ${when.min_risk}`);
  if (when.max_risk !== null && when.max_risk !== undefined) parts.push(`risk ≤ ${when.max_risk}`);
  if (when.level) parts.push(`level ${when.level}`);
  return parts.length ? "when " + parts.join("; ") : "matches anything not caught above";
}

function renderRule(r, total) {
  const dis = editable ? "" : "disabled";
  return `<div class="rule" data-index="${r.index}">
    <div class="ord">${r.index + 1}</div>
    <div class="body">
      <div class="title">
        <span class="act ${esc(r.action)}">${esc(r.action)}${r.approvals ? " ×" + r.approvals : ""}</span>
        <b>${esc(r.name)}</b>
      </div>
      <div class="when">${esc(describeWhen(r.when || {}))}</div>
      ${r.message ? `<div class="msg">${esc(r.message)}</div>` : ""}
    </div>
    <div class="tools">
      <button class="tiny up" title="Earlier: matched sooner" ${r.index === 0 ? "disabled" : dis}>↑</button>
      <button class="tiny down" title="Later" ${r.index === total - 1 ? "disabled" : dis}>↓</button>
      <button class="tiny edit" ${dis}>Edit</button>
      <button class="tiny del" ${dis}>Delete</button>
    </div>
  </div>`;
}

function fillOptions(id, values, selected) {
  const chosen = new Set(selected || []);
  $(id).innerHTML = values
    .map(v => {
      const value = typeof v === "string" ? v : v.id;
      const label = typeof v === "string" ? v : `${v.label} (${v.id})`;
      return `<option value="${esc(value)}" ${chosen.has(value) ? "selected" : ""}>${esc(label)}</option>`;
    })
    .join("");
}

function chosen(id) {
  return Array.from($(id).selectedOptions).map(o => o.value);
}

function csv(id) {
  return $(id).value.split(",").map(s => s.trim()).filter(Boolean);
}

function numberOrNull(id) {
  const v = $(id).value.trim();
  return v === "" ? null : Number(v);
}

function openRuleEditor(index) {
  const p = policyByName(currentPolicy);
  editingIndex = index;
  const r = index === null ? null : p.rules[index];
  const when = (r && r.when) || {};

  $("rule-modal-title").textContent = index === null
    ? `Add a rule to ${currentPolicy}`
    : `Edit rule ${index + 1} of ${currentPolicy}`;
  $("rule-name").value = r ? r.name : "";
  fillOptions("rule-action", vocab.actions, [r ? r.action : "deny"]);
  $("rule-approvals").value = r && r.approvals ? r.approvals : "";
  $("rule-message").value = (r && r.message) || "";
  fillOptions("rule-kinds", vocab.kinds, when.kinds);
  fillOptions("rule-categories", vocab.categories, when.categories);
  fillOptions("rule-flags", vocab.flags, when.flags);
  fillOptions("rule-any-flags", vocab.flags, when.any_flags);
  fillOptions("rule-environments", vocab.environments, when.environments);
  $("rule-objects").value = (when.objects || []).join(", ");
  $("rule-agents").value = (when.agents || []).join(", ");
  $("rule-unfiltered").value = when.unfiltered === true ? "true" : when.unfiltered === false ? "false" : "";
  $("rule-min-risk").value = when.min_risk ?? "";
  $("rule-max-risk").value = when.max_risk ?? "";
  $("rule-error").textContent = "";
  $("rule-test-out").innerHTML = "";
  $("rule-modal").hidden = false;
  $("rule-name").focus();
}

function draftRule() {
  const unfiltered = $("rule-unfiltered").value;
  const approvals = $("rule-approvals").value.trim();
  return {
    name: $("rule-name").value.trim(),
    action: $("rule-action").value,
    approvals: approvals === "" ? null : Number(approvals),
    message: $("rule-message").value.trim() || null,
    when: {
      kinds: chosen("rule-kinds"),
      categories: chosen("rule-categories"),
      objects: csv("rule-objects"),
      agents: csv("rule-agents"),
      flags: chosen("rule-flags"),
      any_flags: chosen("rule-any-flags"),
      environments: chosen("rule-environments"),
      unfiltered: unfiltered === "" ? null : unfiltered === "true",
      min_risk: numberOrNull("rule-min-risk"),
      max_risk: numberOrNull("rule-max-risk"),
    },
  };
}

async function saveRule() {
  const rule = draftRule();
  if (!rule.name) {
    $("rule-error").textContent = "Give the rule a name.";
    return;
  }
  try {
    if (editingIndex === null) {
      await api(`/api/policies/${encodeURIComponent(currentPolicy)}/rules`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rule),
      });
    } else {
      await api(`/api/policies/${encodeURIComponent(currentPolicy)}/rules/${editingIndex}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rule),
      });
    }
    $("rule-modal").hidden = true;
    await loadPolicies();
  } catch (e) {
    $("rule-error").textContent = e.message;
  }
}

async function testRule() {
  const sql = $("rule-test-sql").value.trim();
  if (!sql) return;
  const out = $("rule-test-out");
  try {
    const result = await api("/api/policies/try", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sql, policy: currentPolicy, rule: draftRule() }),
    });
    const before = result.without_rule;
    const after = result.with_rule;
    const line = (label, v) => `
      <div class="fact">
        <div class="k">${esc(label)}</div>
        <div class="v"><span class="act ${esc(v.decision)}">${esc(v.decision)}</span>
          risk ${v.risk}${v.statements[0] && v.statements[0].matched_rule
            ? ` · matched "${esc(v.statements[0].matched_rule)}"` : ""}</div>
      </div>`;
    out.innerHTML = `<div class="facts" style="margin-top:10px">
      ${line("as it is now", before)}
      ${after ? line("with this rule", after) : ""}
    </div>${
      after && !result.changed
        ? `<div class="hint">This rule does not change the outcome for that statement. Either an
             earlier rule already decides it, or the match conditions do not fit.</div>`
        : ""
    }`;
  } catch (e) {
    out.innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }
}

$("policy-select").addEventListener("change", (e) => {
  currentPolicy = e.target.value;
  renderPolicy();
});

$("policy-settings").addEventListener("change", async (e) => {
  const key = e.target.dataset.setting;
  if (!key) return;
  let value;
  if (e.target.tagName === "SELECT") {
    value = e.target.value === "true" ? true : e.target.value === "false" ? false : e.target.value;
  } else {
    value = e.target.value.trim() === "" ? null : Number(e.target.value);
  }
  try {
    await api(`/api/policies/${encodeURIComponent(currentPolicy)}/settings`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ [key]: value }),
    });
    await loadPolicies();
  } catch (err) {
    alert(err.message);
    await loadPolicies();
  }
});

$("rules-list").addEventListener("click", async (event) => {
  const row = event.target.closest(".rule");
  if (!row) return;
  const index = Number(row.dataset.index);
  const base = `/api/policies/${encodeURIComponent(currentPolicy)}/rules/${index}`;
  try {
    if (event.target.classList.contains("edit")) return openRuleEditor(index);
    if (event.target.classList.contains("del")) {
      if (!confirm("Delete this rule? The proxy stops enforcing it immediately.")) return;
      await api(base, { method: "DELETE" });
    } else if (event.target.classList.contains("up")) {
      await api(`${base}/move`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ to: index - 1 }),
      });
    } else if (event.target.classList.contains("down")) {
      await api(`${base}/move`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ to: index + 1 }),
      });
    } else {
      return;
    }
    await loadPolicies();
  } catch (e) {
    alert(e.message);
  }
});

$("rule-add").addEventListener("click", () => openRuleEditor(null));
$("rule-save").addEventListener("click", saveRule);
$("rule-test").addEventListener("click", testRule);
$("rule-test-sql").addEventListener("keydown", (e) => { if (e.key === "Enter") testRule(); });
for (const id of ["rule-close", "rule-cancel"]) {
  $(id).addEventListener("click", () => { $("rule-modal").hidden = true; });
}

$("policy-reload").addEventListener("click", async () => {
  try {
    await api("/api/config/reload", { method: "POST" });
    await loadPolicies();
  } catch (e) {
    alert(e.message);
  }
});

$("policy-raw").addEventListener("click", async () => {
  try {
    const body = await api("/api/config");
    $("toml-text").value = body.toml;
    $("toml-text").readOnly = !body.editable;
    $("toml-save").disabled = !body.editable;
    $("toml-error").textContent = "";
    $("toml-modal").hidden = false;
  } catch (e) {
    alert(e.message);
  }
});

$("toml-save").addEventListener("click", async () => {
  try {
    await api("/api/config", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ toml: $("toml-text").value }),
    });
    $("toml-modal").hidden = true;
    await loadPolicies();
  } catch (e) {
    $("toml-error").textContent = e.message;
  }
});

for (const id of ["toml-close", "toml-cancel"]) {
  $(id).addEventListener("click", () => { $("toml-modal").hidden = true; });
}

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  $("rule-modal").hidden = true;
  $("toml-modal").hidden = true;
});

// Deliberately not part of the five-second refresh: re-rendering the rule list
// under somebody who is halfway through changing a threshold would take the
// focus out of the field they are typing in. Rules reload after an edit, and on
// demand.
async function refresh() {
  try {
    await Promise.all([
      loadSummary(),
      api("/api/approvals").then(r => renderApprovals(r.approvals)),
      loadAudit(),
    ]);
  } catch (e) {
    console.error(e);
  }
}

// Live updates: an approval request should appear the moment it is raised,
// not on the next poll. The interval is a fallback for when the stream drops.
const events = new EventSource("/api/stream");
events.addEventListener("approval", refresh);
setInterval(refresh, 5000);
window.addEventListener("resize", () => loadSummary().catch(() => {}));
refresh();
loadPolicies().catch((e) => {
  document.getElementById("rules-list").innerHTML =
    `<div class="empty">Could not load policies: ${esc(e.message)}</div>`;
});
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_is_self_contained() {
        // A dashboard that fetches from a CDN is a dashboard that stops
        // working on an air-gapped network, and a supply chain nobody audited.
        for offender in ["http://", "https://", "//cdn", "integrity="] {
            assert!(
                !PAGE.contains(offender),
                "the dashboard references something external: {offender}"
            );
        }
    }

    #[test]
    fn the_page_escapes_what_it_renders() {
        // Statement text comes from an agent. It reaches the DOM through esc().
        assert!(PAGE.contains("const esc ="));
        assert!(PAGE.contains("replace(/[&<>\"']/g"));
    }

    #[tokio::test]
    async fn the_page_is_served() {
        let Html(body) = index().await;
        assert!(body.starts_with("<!doctype html>"));
    }
}
