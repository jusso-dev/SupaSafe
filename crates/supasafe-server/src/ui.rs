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

  <h2>Recent statements</h2>
  <div class="panel scroll" id="audit"><div class="empty">No statements yet.</div></div>
</main>

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
