# dashboard.py

from flask import Flask, jsonify, render_template_string
from db import (get_all_risk_scores, get_user_sessions,
                get_recent_events, get_dashboard_stats, get_user_insight)

app = Flask(__name__)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>C-PAM SOC Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0f1117; --surface: #1a1d27; --surface2: #21253a;
      --border: #2a2d3a; --text: #e2e4ef; --muted: #8b8fa8;
      --critical: #ef4444; --high: #f97316; --medium: #eab308;
      --low: #22c55e; --info: #3b82f6; --anomaly: #a855f7;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.5; }

    header { padding: 16px 28px; border-bottom: 1px solid var(--border);
             display: flex; align-items: center; justify-content: space-between;
             background: var(--surface); position: sticky; top: 0; z-index: 50; }
    header h1 { font-size: 16px; font-weight: 600; }
    .live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
                background: var(--low); margin-right: 6px;
                animation: pulse 2s ease-in-out infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }

    /* Nav tabs */
    .nav { display: flex; gap: 4px; padding: 16px 28px 0;
           border-bottom: 1px solid var(--border); background: var(--surface); }
    .nav-tab { padding: 10px 20px; border-radius: 6px 6px 0 0; cursor: pointer;
               font-size: 13px; color: var(--muted); border: 1px solid transparent;
               border-bottom: none; transition: all 0.15s; user-select: none; }
    .nav-tab:hover { color: var(--text); background: var(--surface2); }
    .nav-tab.active { color: var(--text); background: var(--bg);
                      border-color: var(--border); font-weight: 500; }

    /* Pages */
    .page { display: none; padding: 24px 28px; max-width: 1400px; margin: 0 auto; }
    .page.active { display: block; }

    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr));
             gap: 14px; margin-bottom: 24px; }
    .stat-card { background: var(--surface); border: 1px solid var(--border);
                 border-radius: 10px; padding: 16px 20px; }
    .stat-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase;
                        letter-spacing: 0.08em; margin-bottom: 6px; }
    .stat-card .value { font-size: 28px; font-weight: 700; }
    .stat-card.critical .value { color: var(--critical); }
    .stat-card.anomaly  .value { color: var(--anomaly); }
    .stat-card.info     .value { color: var(--info); }

    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
    .card { background: var(--surface); border: 1px solid var(--border);
            border-radius: 10px; padding: 20px; margin-bottom: 20px; }
    .card h2 { font-size: 11px; font-weight: 600; color: var(--muted);
               text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 16px; }

    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 8px 10px; color: var(--muted); font-size: 11px;
         text-transform: uppercase; letter-spacing: 0.06em;
         border-bottom: 1px solid var(--border); }
    td { padding: 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tbody tr { cursor: pointer; transition: background 0.15s; }
    tbody tr:hover td { background: rgba(255,255,255,0.03); }

    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-size: 11px; font-weight: 600; letter-spacing: 0.04em; }
    .badge.CRITICAL { background: rgba(239,68,68,0.15);  color: var(--critical); }
    .badge.HIGH     { background: rgba(249,115,22,0.15); color: var(--high); }
    .badge.MEDIUM   { background: rgba(234,179,8,0.15);  color: var(--medium); }
    .badge.LOW      { background: rgba(34,197,94,0.15);  color: var(--low); }
    .badge.ANOMALY  { background: rgba(168,85,247,0.15); color: var(--anomaly); }
    .badge.NORMAL   { background: rgba(139,143,168,0.15);color: var(--muted); }
    .badge.PENDING  { background: rgba(59,130,246,0.15); color: var(--info); }

    .risk-bar-wrap { width: 100px; height: 6px; background: var(--border);
                     border-radius: 3px; overflow: hidden; }
    .risk-bar { height: 100%; border-radius: 3px; }

    /* Activity tracking page */
    .user-grid { display: grid; grid-template-columns: 240px 1fr; gap: 0;
                 background: var(--surface); border: 1px solid var(--border);
                 border-radius: 10px; overflow: hidden; min-height: 600px; }
    .user-list { border-right: 1px solid var(--border); overflow-y: auto; }
    .user-list-header { padding: 14px 16px; font-size: 11px; font-weight: 600;
                        color: var(--muted); text-transform: uppercase;
                        letter-spacing: 0.07em; border-bottom: 1px solid var(--border); }
    .user-item { padding: 12px 16px; cursor: pointer; border-bottom: 1px solid var(--border);
                 transition: background 0.15s; display: flex; align-items: center;
                 justify-content: space-between; }
    .user-item:hover { background: var(--surface2); }
    .user-item.active { background: var(--surface2); border-left: 2px solid var(--info); }
    .user-item .uname { font-weight: 500; font-size: 13px; }
    .user-item .ulevel { font-size: 11px; }

    .session-detail { padding: 20px; overflow-y: auto; }
    .detail-header { display: flex; align-items: center; justify-content: space-between;
                     margin-bottom: 20px; padding-bottom: 16px;
                     border-bottom: 1px solid var(--border); }
    .detail-header h3 { font-size: 16px; font-weight: 600; }

    .session-tabs { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }
    .sess-tab { padding: 6px 14px; border-radius: 20px; cursor: pointer; font-size: 12px;
                background: var(--surface2); color: var(--muted);
                border: 1px solid var(--border); transition: all 0.15s; }
    .sess-tab:hover { color: var(--text); }
    .sess-tab.active { background: var(--info); color: #fff; border-color: var(--info); }

    .sess-panel { display: none; }
    .sess-panel.active { display: block; }

    .sess-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr));
                 gap: 12px; margin-bottom: 16px; }
    .meta-box { background: var(--surface2); border-radius: 8px; padding: 12px; }
    .meta-box .ml { font-size: 11px; color: var(--muted); margin-bottom: 4px; }
    .meta-box .mv { font-size: 18px; font-weight: 700; }
    .meta-box.warn .mv { color: var(--critical); }

    .action-timeline { background: var(--bg); border-radius: 8px; padding: 12px 16px;
                       max-height: 260px; overflow-y: auto; }
    .action-row { display: flex; align-items: flex-start; gap: 10px;
                  padding: 6px 0; border-bottom: 1px solid var(--border);
                  font-size: 12px; }
    .action-row:last-child { border-bottom: none; }
    .action-num  { color: var(--muted); min-width: 28px; text-align: right; }
    .action-cmd  { font-family: monospace; color: var(--text); flex: 1; word-break: break-all; }
    .action-cmd.danger { color: var(--critical); }
    .action-cmd.priv   { color: var(--high); }

    .insight-box { background: rgba(168,85,247,0.07); border: 1px solid rgba(168,85,247,0.25);
                   border-radius: 8px; padding: 16px; margin-bottom: 20px; }
    .insight-label { font-size: 11px; font-weight: 600; color: var(--anomaly);
                     text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 10px; }
    .insight-text { font-size: 12px; line-height: 1.8; white-space: pre-wrap; color: var(--text); }

    .event-log { max-height: 340px; overflow-y: auto; font-size: 12px; }
    .event-row { display: flex; gap: 10px; padding: 7px 4px;
                 border-bottom: 1px solid var(--border); align-items: flex-start; }
    .event-row:last-child { border-bottom: none; }
    .event-ts     { color: var(--muted); white-space: nowrap; min-width: 150px; }
    .event-user   { font-weight: 600; min-width: 80px; }
    .event-action { color: var(--text); flex: 1; word-break: break-all; font-family: monospace; }
    .event-src    { color: var(--muted); font-size: 11px; min-width: 70px; text-align: right; }

    canvas { max-height: 200px; }
    ::-webkit-scrollbar { width: 5px; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  </style>
</head>
<body>

<header>
  <h1><span class="live-dot"></span>C-PAM — Continuous Privileged Access Monitor</h1>
  <span id="last-refresh" style="font-size:12px;color:var(--muted)">Loading...</span>
</header>

<!-- Nav tabs -->
<div class="nav">
  <div class="nav-tab active" onclick="showPage('overview')">Overview</div>
  <div class="nav-tab" onclick="showPage('tracking')">User Activity Tracking</div>
  <div class="nav-tab" onclick="showPage('events')">Event Log</div>
  <div class="nav-tab" onclick="showPage('alerts')">
    Live Alerts <span id="alert-badge" style="
    background:var(--critical);color:#fff;border-radius:10px;
    padding:1px 6px;font-size:10px;margin-left:4px;display:none">0</span>
  </div>
</div>

<!-- PAGE: Overview -->
<div class="page active" id="page-overview">
  <div class="stats" id="stats-row"></div>
  <div class="grid-2">
    <div class="card"><h2>Risk distribution</h2><canvas id="riskChart"></canvas></div>
    <!--<div class="card"><h2>ML vs rule flags</h2><canvas id="flagChart"></canvas></div>-->
  </div>
  <div class="card">
    <h2>User risk scores</h2>
    <table>
      <thead><tr>
        <th>User</th><th>Risk level</th><th>ML anomaly</th><th>Verdict</th>
        </tr></thead>
      <!--</tr></thead>-->
      <tbody id="risk-table-body"></tbody>
    </table>
  </div>
</div>

<!-- PAGE: User Activity Tracking -->
<div class="page" id="page-tracking">
  <div class="user-grid">
    <div class="user-list">
      <div class="user-list-header">Users</div>
      <div id="user-list-body"></div>
    </div>
    <div class="session-detail" id="session-detail">
      <div style="color:var(--muted);padding:40px;text-align:center">
        Select a user to view their session activity
      </div>
    </div>
  </div>
</div>

<!-- PAGE: Event Log -->
<div class="page" id="page-events">
  <div class="card">
    <h2>Recent events (last 200)</h2>
    <div class="event-log" id="event-log"></div>
  </div>
</div>

<!-- PAGE: Live Alerts -->
<div class="page" id="page-alerts">
  <div class="card">
    <h2>Real-time alerts</h2>
    <div style="font-size:12px;color:var(--muted);margin-bottom:16px">
      Triggered instantly when suspicious actions are detected. AI summary generated per alert.
    </div>
    <div id="alerts-feed"></div>
  </div>
</div>

<script>
let riskChart, flagChart;
let allRiskData = [];

async function loadUserList() {
  const users = await fetch('/api/users').then(r => r.json());

  document.getElementById('risk-table-body').innerHTML = rows.map(r => `
    <tr onclick="goToUser('${r.user}')">
      <td><strong>${r.user}</strong></td>
      <td><span class="badge ${r.risk_level}">${r.risk_level}</span></td>
      <td><span class="badge ${r.ml_flag}">${r.ml_flag}</span></td>
      <td><span class="badge ${r.final_verdict}">${r.final_verdict}</span></td>
    </tr>`).join('');

  // Auto-select the highest risk user
  if (users.length > 0) loadUserDetail(users[0].user);
}

function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'events')   loadEvents();
  if (name === 'tracking') loadUserList();  // always reload user list fresh
  if (name === 'alerts') {
    loadAlerts();
      document.getElementById('alert-badge').style.display = 'none';
      lastAlertCount = 0; // reset count when viewing alerts page
  }
}

function barColor(level) {
  return {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#22c55e'}[level]||'#3b82f6';
}

function actionClass(action) {
  if (['rm -rf','dd if=','mkfs','shred'].some(k => action.includes(k))) return 'danger';
  if (action === 'sudo' || action.startsWith('sudo ')) return 'priv';
  if (action === 'login_failed') return 'danger';
  return '';
}

let lastAlertCount = 0;

async function loadAlerts() {
  const alerts = await fetch('/api/alerts').then(r => r.json());
  document.getElementById('alerts-feed').innerHTML = alerts.length === 0
    ? '<div style="color:var(--muted);padding:20px;text-align:center">No alerts yet — monitor.py will populate this in real time.</div>'
    : alerts.map(a => `
        <div style="border:1px solid var(--border);border-radius:8px;padding:16px;
                    margin-bottom:12px;border-left:3px solid ${alertColor(a.risk_level)}">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <div style="display:flex;align-items:center;gap:10px">
              <strong>${a.user}</strong>
              <span class="badge ${a.risk_level}">${a.risk_level}</span>
              <code style="font-size:11px;background:var(--surface2);
                           padding:2px 6px;border-radius:4px">${a.action}</code>
            </div>
            <span style="font-size:11px;color:var(--muted)">${a.timestamp}</span>
          </div>
          <div style="font-size:13px;line-height:1.6;color:var(--text)">${a.summary}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:6px">
            Risk at time of alert: ${a.risk_score}%
          </div>
        </div>`).join('');
}

function alertColor(level) {
  return {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#22c55e'}[level]||'#3b82f6';
}

async function checkAlertBadge() {
  const d = await fetch('/api/alerts/count').then(r => r.json());
  const badge = document.getElementById('alert-badge');
  if (d.count > lastAlertCount) {
    badge.style.display = 'inline';
    badge.textContent = d.count;
    lastAlertCount = d.count;
  }
}

async function loadStats() {
  const d = await fetch('/api/stats').then(r => r.json());
  document.getElementById('stats-row').innerHTML = `
    <div class="stat-card"><div class="label">Total users</div><div class="value">${d.total_users}</div></div>
    <div class="stat-card critical"><div class="label">Critical risk</div><div class="value">${d.critical_users}</div></div>
    <div class="stat-card anomaly"><div class="label">Anomalies</div><div class="value">${d.anomaly_users}</div></div>
    <div class="stat-card info"><div class="label">Total events</div><div class="value">${d.total_events}</div></div>
    <div class="stat-card"><div class="label">Suspicious sessions</div><div class="value">${d.suspicious_sessions}</div></div>
  `;
}

async function loadRiskTable() {
  const rows = await fetch('/api/risk').then(r => r.json());
  allRiskData = rows;

  const counts    = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  const mlCounts  = {ANOMALY:0,NORMAL:0};
  const ruleCounts= {ANOMALY:0,NORMAL:0};
  rows.forEach(r => {
    counts[r.risk_level]       = (counts[r.risk_level]||0)+1;
    mlCounts[r.ml_flag]        = (mlCounts[r.ml_flag]||0)+1;
    ruleCounts[r.rule_flag]    = (ruleCounts[r.rule_flag]||0)+1;
  });

  if (riskChart) riskChart.destroy();
  riskChart = new Chart(document.getElementById('riskChart'), {
    type: 'doughnut',
    data: { labels:['Critical','High','Medium','Low'],
      datasets:[{data:[counts.CRITICAL,counts.HIGH,counts.MEDIUM,counts.LOW],
        backgroundColor:['#ef4444','#f97316','#eab308','#22c55e'],borderWidth:0}]},
    options:{plugins:{legend:{labels:{color:'#8b8fa8',font:{size:12}}}},cutout:'65%'}
  });

  if (flagChart) flagChart.destroy();
  flagChart = new Chart(document.getElementById('flagChart'),{
    type:'bar',
    data:{labels:['ML Anomaly','ML Normal','Rule Anomaly','Rule Normal'],
      datasets:[{data:[mlCounts.ANOMALY,mlCounts.NORMAL,ruleCounts.ANOMALY,ruleCounts.NORMAL],
        backgroundColor:['#a855f7','#3b82f6','#ef4444','#22c55e'],borderRadius:4,borderWidth:0}]},
    options:{plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:'#8b8fa8',font:{size:11}},grid:{color:'#2a2d3a'}},
              y:{ticks:{color:'#8b8fa8',font:{size:11}},grid:{color:'#2a2d3a'}}}}
  });

  document.getElementById('risk-table-body').innerHTML = rows.map(r => `
    <tr onclick="goToUser('${r.user}')">
      <td><strong>${r.user}</strong></td>
      <td><span class="badge ${r.risk_level}">${r.risk_level}</span></td>
      <td><span class="badge ${r.ml_flag}">${r.ml_flag}</span></td>
      <td><span class="badge ${r.final_verdict}">${r.final_verdict}</span></td>
    </tr>`).join('');

  // Populate user list in tracking tab (deduplicated)
  const seen = new Set();
  const unique = rows.filter(r => { if(seen.has(r.user)) return false; seen.add(r.user); return true; });
  document.getElementById('user-list-body').innerHTML = unique.map(r => `
    <div class="user-item" id="uitem-${r.user}" onclick="loadUserDetail('${r.user}')">
      <span class="uname">${r.user}</span>
      <span class="badge ${r.risk_level} ulevel">${r.risk_level}</span>
    </div>`).join('');
}

async function loadEvents() {
  const events = await fetch('/api/events').then(r => r.json());
  document.getElementById('event-log').innerHTML = events.map(e => `
    <div class="event-row">
      <span class="event-ts">${e.timestamp||'—'}</span>
      <span class="event-user">${e.user}</span>
      <span class="event-action">${e.action}</span>
      <span class="event-src">${e.source}</span>
    </div>`).join('');
}

// Navigate from risk table row → tracking tab for that user
function goToUser(user) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-tracking').classList.add('active');
  document.querySelectorAll('.nav-tab')[1].classList.add('active');
  loadUserDetail(user);
}

async function loadUserDetail(user) {
  // Highlight selected user
  document.querySelectorAll('.user-item').forEach(el => el.classList.remove('active'));
  const item = document.getElementById('uitem-' + user);
  if (item) item.classList.add('active');

  const [sessions, insightData, riskRow] = await Promise.all([
    fetch('/api/sessions/' + user).then(r => r.json()),
    fetch('/api/insight/'  + user).then(r => r.json()),
    Promise.resolve(allRiskData.find(r => r.user === user) || {}),
  ]);

  const detail = document.getElementById('session-detail');

  // Header
  const verdict = riskRow.final_verdict || 'NORMAL';
  const level   = riskRow.risk_level    || 'LOW';
  let html = `
    <div class="detail-header">
      <div>
        <h3>${user}</h3>
        <div style="margin-top:6px;display:flex;gap:8px;align-items:center">
          <span class="badge ${level}">${level} — ${riskRow.normalized_risk||0}%</span>
          <span class="badge ${verdict}">${verdict}</span>
          <span style="font-size:12px;color:var(--muted)">${sessions.length} session(s)</span>
        </div>
      </div>
    </div>`;

  // AI insight
  if (insightData.insight && !insightData.insight.startsWith('No suspicious')) {
    html += `
      <div class="insight-box">
        <div class="insight-label">AI Threat Assessment
          ${insightData.highest_severity !== 'NONE'
            ? '&nbsp;<span class="badge '+insightData.highest_severity+'">'+insightData.highest_severity+'</span>'
            : ''}
        </div>
        <div class="insight-text">${insightData.insight}</div>
      </div>`;
  }

  // Session tabs
  if (sessions.length === 0) {
    html += `<div style="color:var(--muted);padding:20px">No sessions recorded for this user.</div>`;
  } else {
    html += `<div class="session-tabs">`;
    sessions.forEach((s, i) => {
      const flag = s.suspicious_sequence ? '⚠ ' : '';
      html += `<div class="sess-tab ${i===0?'active':''}"
                    onclick="switchSession(${i})"
                    id="stab-${i}">${flag}${s.session_id}</div>`;
    });
    html += `</div>`;

    sessions.forEach((s, i) => {
      const actions = s.actions || [];
      html += `
        <div class="sess-panel ${i===0?'active':''}" id="spanel-${i}">
          <div class="sess-meta">
            <div class="meta-box">
              <div class="ml">Login time</div>
              <div class="mv" style="font-size:13px;font-weight:500">${s.login_time||'—'}</div>
            </div>
            <div class="meta-box">
              <div class="ml">Logout time</div>
              <div class="mv" style="font-size:13px;font-weight:500">${s.logout_time||'Not seen'}</div>
            </div>
            <div class="meta-box">
              <div class="ml">Duration</div>
              <div class="mv">${s.duration_seconds!=null ? s.duration_seconds+'s' : 'Open'}</div>
            </div>
            <div class="meta-box">
              <div class="ml">Total actions</div>
              <div class="mv">${s.action_count}</div>
            </div>
            <div class="meta-box ${s.sudo_count>0?'warn':''}">
              <div class="ml">Sudo count</div>
              <div class="mv">${s.sudo_count}</div>
            </div>
            <div class="meta-box ${s.failed_logins>=3?'warn':''}">
              <div class="ml">Failed logins</div>
              <div class="mv">${s.failed_logins}</div>
            </div>
            <div class="meta-box ${s.destructive_count>0?'warn':''}">
              <div class="ml">Destructive cmds</div>
              <div class="mv">${s.destructive_count}</div>
            </div>
            <div class="meta-box ${s.suspicious_sequence?'warn':''}">
              <div class="ml">Suspicious seq.</div>
              <div class="mv" style="font-size:13px">${s.suspicious_sequence?'YES ⚠':'No'}</div>
            </div>
          </div>
          <div style="font-size:11px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.07em">
            Action timeline — ${actions.length} events
          </div>
          <div class="action-timeline">
            ${actions.map((a,idx) => `
              <div class="action-row">
                <span class="action-num">${idx+1}</span>
                <span class="action-cmd ${actionClass(a)}">${a}</span>
              </div>`).join('')}
          </div>
          <div id="sess-insight-${i}" style="margin-top:12px;font-size:12px;
            color:var(--muted);font-style:italic;padding:8px 0">
            Loading session summary...
          </div>
        </div>`;
    });
  }

  detail.innerHTML = html;

  // FIXED: Load session insights AFTER DOM render
  setTimeout(() => {
    sessions.forEach((s, i) => {
      const el = document.getElementById('sess-insight-' + i);
      if (!el) return;

      el.innerHTML = '<span style="color:var(--muted);font-size:11px">Loading summary...</span>';

      fetch('/api/session-insight/' + encodeURIComponent(s.session_id))
        .then(r => r.json())
        .then(d => {
          if (el) {
            el.innerHTML = d.insight
              ? `<div style="background:rgba(59,130,246,0.07);
                     border:1px solid rgba(59,130,246,0.2);
                     border-radius:6px;padding:10px;margin-top:10px;
                     line-height:1.7;color:var(--text);font-size:12px">
                     <span style="font-size:10px;font-weight:600;
                     color:var(--info);text-transform:uppercase;
                     letter-spacing:0.07em;display:block;margin-bottom:6px">
                     Session Summary</span>
                     ${d.insight}</div>`
              : '<span style="color:var(--muted);font-size:11px">No summary available for this session.</span>';
          }
        })
        .catch(() => {
          if (el) el.innerHTML = '';
        });
    });
  }, 100);
}

 /*   detail.innerHTML = html;

  // Load session insights async
  sessions.forEach((s, i) => {
    fetch('/api/session-insight/' + s.session_id)
      .then(r => r.json())
        .then(d => {
            const el = document.getElementById('sess-insight-' + i);
            if (el) el.innerHTML = d.insight
                ? `<div style="background:rgba(59,130,246,0.07);border:1px solid
                   rgba(59,130,246,0.2);border-radius:6px;padding:10px;
                   margin-top:8px;line-height:1.7;color:var(--text);
                   font-style:normal">${d.insight}</div>`
                : '';
        });
  });
}*/

function switchSession(idx) {
  document.querySelectorAll('.sess-tab').forEach((t,i) => t.classList.toggle('active', i===idx));
  document.querySelectorAll('.sess-panel').forEach((p,i) => p.classList.toggle('active', i===idx));
}

async function refresh() {
  await Promise.all([loadStats(), loadRiskTable(), checkAlertBadge()]);
  document.getElementById('last-refresh').textContent =
    'Last refresh: ' + new Date().toLocaleTimeString();
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/stats")
def api_stats():
    return jsonify(get_dashboard_stats())

@app.route("/api/risk")
def api_risk():
    return jsonify(get_all_risk_scores())

@app.route("/api/sessions/<user>")
def api_sessions(user):
    return jsonify(get_user_sessions(user))

@app.route("/api/events")
def api_events():
    return jsonify(get_recent_events())

@app.route("/api/insight/<user>")
def api_insight(user):
    return jsonify(get_user_insight(user))

@app.route("/api/users")
def api_users():
    from db import get_connection
    conn = get_connection()
    rows = conn.execute("""
        SELECT DISTINCT r.user, r.normalized_risk, r.risk_level, r.final_verdict
        FROM risk_scores r
        ORDER BY r.normalized_risk DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/alerts")
def api_alerts():
    from db import get_connection
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT * FROM realtime_alerts
            ORDER BY timestamp DESC LIMIT 50
        """).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        return jsonify([])
    finally:
        conn.close()

@app.route("/api/alerts/count")
def api_alerts_count():
    from db import get_connection
    conn = get_connection()
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM realtime_alerts"
        ).fetchone()[0]
        return jsonify({"count": count})
    except Exception:
        return jsonify({"count": 0})
    finally:
        conn.close()

@app.route("/api/session-insight/<session_id>")
def api_session_insight(session_id):
    from db import get_session_insight
    return jsonify({"insight": get_session_insight(session_id)})

if __name__ == "__main__":
    print("C-PAM Dashboard → http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)