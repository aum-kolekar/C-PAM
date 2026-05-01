# dashboard.py
# Run with: python dashboard.py
# Open browser at: http://localhost:5000

from flask import Flask, jsonify, render_template_string
from db import get_all_risk_scores, get_user_sessions, get_recent_events, get_dashboard_stats

app = Flask(__name__)

# ── HTML template (single file, no separate templates folder needed) ──────────

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>C-PAM — SOC Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:       #0f1117;
      --surface:  #1a1d27;
      --border:   #2a2d3a;
      --text:     #e2e4ef;
      --muted:    #8b8fa8;
      --critical: #ef4444;
      --high:     #f97316;
      --medium:   #eab308;
      --low:      #22c55e;
      --info:     #3b82f6;
      --anomaly:  #a855f7;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--bg);
      color: var(--text);
      font-size: 14px;
      line-height: 1.5;
    }

    header {
      padding: 16px 28px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--surface);
    }
    header h1 { font-size: 18px; font-weight: 600; letter-spacing: 0.02em; }
    header span { font-size: 12px; color: var(--muted); }

    .live-dot {
      display: inline-block; width: 8px; height: 8px;
      border-radius: 50%; background: var(--low);
      margin-right: 6px;
      animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

    main { padding: 24px 28px; max-width: 1400px; margin: 0 auto; }

    /* ── Stat cards ── */
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px 20px;
    }
    .stat-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; }
    .stat-card .value { font-size: 30px; font-weight: 700; }
    .stat-card.critical .value { color: var(--critical); }
    .stat-card.anomaly  .value { color: var(--anomaly); }
    .stat-card.info     .value { color: var(--info); }

    /* ── Grid layout ── */
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
    .grid-1 { margin-bottom: 20px; }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
    }
    .card h2 { font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 16px; }

    /* ── Risk table ── */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 8px 10px; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; border-bottom: 1px solid var(--border); }
    td { padding: 10px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr { cursor: pointer; transition: background 0.15s; }
    tr:hover td { background: rgba(255,255,255,0.03); }

    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.04em;
    }
    .badge.CRITICAL { background: rgba(239,68,68,0.15);  color: var(--critical); }
    .badge.HIGH     { background: rgba(249,115,22,0.15); color: var(--high); }
    .badge.MEDIUM   { background: rgba(234,179,8,0.15);  color: var(--medium); }
    .badge.LOW      { background: rgba(34,197,94,0.15);  color: var(--low); }
    .badge.ANOMALY  { background: rgba(168,85,247,0.15); color: var(--anomaly); }
    .badge.NORMAL   { background: rgba(139,143,168,0.15);color: var(--muted); }

    /* ── Risk bar ── */
    .risk-bar-wrap { width: 100px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
    .risk-bar { height: 100%; border-radius: 3px; transition: width 0.3s; }

    /* ── Event log ── */
    .event-log { max-height: 320px; overflow-y: auto; font-size: 12px; }
    .event-row { display: flex; gap: 10px; padding: 7px 4px; border-bottom: 1px solid var(--border); align-items: flex-start; }
    .event-row:last-child { border-bottom: none; }
    .event-ts   { color: var(--muted); white-space: nowrap; min-width: 140px; }
    .event-user { font-weight: 600; min-width: 90px; }
    .event-action { color: var(--text); flex: 1; word-break: break-all; }
    .event-source { color: var(--muted); font-size: 11px; min-width: 70px; text-align: right; }

    /* ── Session modal ── */
    .modal-bg {
      display: none; position: fixed; inset: 0;
      background: rgba(0,0,0,0.7); z-index: 100;
      align-items: center; justify-content: center;
    }
    .modal-bg.open { display: flex; }
    .modal {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 28px; width: 700px; max-height: 80vh;
      overflow-y: auto;
    }
    .modal h3 { font-size: 15px; margin-bottom: 16px; }
    .modal-close { float: right; cursor: pointer; color: var(--muted); font-size: 20px; line-height: 1; }

    .session-block {
      border: 1px solid var(--border); border-radius: 8px;
      padding: 14px; margin-bottom: 12px; font-size: 12px;
    }
    .session-block .sh { display: flex; justify-content: space-between; margin-bottom: 8px; }
    .session-block .st { font-weight: 600; }
    .session-actions {
      background: var(--bg); border-radius: 6px;
      padding: 8px 10px; font-family: monospace; font-size: 11px;
      max-height: 100px; overflow-y: auto; color: var(--muted);
      word-break: break-all; line-height: 1.8;
    }

    canvas { max-height: 220px; }
    ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  </style>
</head>
<body>

<header>
  <h1><span class="live-dot"></span>C-PAM — Continuous Privileged Access Monitor</h1>
  <span id="last-refresh">Loading...</span>
</header>

<main>

  <!-- Stat cards -->
  <div class="stats" id="stats-row"></div>

  <!-- Charts row -->
  <div class="grid-2">
    <div class="card">
      <h2>Risk distribution</h2>
      <canvas id="riskChart"></canvas>
    </div>
    <div class="card">
      <h2>ML vs rule flags</h2>
      <canvas id="flagChart"></canvas>
    </div>
  </div>

  <!-- Risk table -->
  <div class="card grid-1">
    <h2>User risk scores</h2>
    <table>
      <thead>
        <tr>
          <th>User</th>
          <th>Risk score</th>
          <th>Level</th>
          <th>ML flag</th>
          <th>Rule flag</th>
          <th>Verdict</th>
        </tr>
      </thead>
      <tbody id="risk-table-body"></tbody>
    </table>
  </div>

  <!-- Event log -->
  <div class="card grid-1">
    <h2>Recent events (last 200)</h2>
    <div class="event-log" id="event-log"></div>
  </div>

</main>

<!-- Session detail modal -->
<div class="modal-bg" id="modal-bg" onclick="closeModal(event)">
  <div class="modal">
    <span class="modal-close" onclick="document.getElementById('modal-bg').classList.remove('open')">×</span>
    <h3 id="modal-title">Sessions</h3>
    <div id="modal-body"></div>
  </div>
</div>

<script>
let riskChart, flagChart;

function barColor(level) {
  return { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#22c55e' }[level] || '#3b82f6';
}

async function loadStats() {
  const r = await fetch('/api/stats');
  const d = await r.json();
  document.getElementById('stats-row').innerHTML = `
    <div class="stat-card"><div class="label">Total users</div><div class="value">${d.total_users}</div></div>
    <div class="stat-card critical"><div class="label">Critical risk</div><div class="value">${d.critical_users}</div></div>
    <div class="stat-card anomaly"><div class="label">Anomalies</div><div class="value">${d.anomaly_users}</div></div>
    <div class="stat-card info"><div class="label">Total events</div><div class="value">${d.total_events}</div></div>
    <div class="stat-card"><div class="label">Suspicious sessions</div><div class="value">${d.suspicious_sessions}</div></div>
  `;
}

async function loadRiskTable() {
  const r = await fetch('/api/risk');
  const rows = await r.json();

  // Risk distribution chart
  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  const mlCounts = { ANOMALY:0, NORMAL:0 };
  const ruleCounts = { ANOMALY:0, NORMAL:0 };

  rows.forEach(r => {
    counts[r.risk_level] = (counts[r.risk_level] || 0) + 1;
    mlCounts[r.ml_flag]   = (mlCounts[r.ml_flag]   || 0) + 1;
    ruleCounts[r.rule_flag] = (ruleCounts[r.rule_flag] || 0) + 1;
  });

  if (riskChart) riskChart.destroy();
  riskChart = new Chart(document.getElementById('riskChart'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{ data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
        backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e'], borderWidth: 0 }]
    },
    options: { plugins: { legend: { labels: { color:'#8b8fa8', font:{size:12} } } }, cutout:'65%' }
  });

  if (flagChart) flagChart.destroy();
  flagChart = new Chart(document.getElementById('flagChart'), {
    type: 'bar',
    data: {
      labels: ['ML Anomaly','ML Normal','Rule Anomaly','Rule Normal'],
      datasets: [{ data: [mlCounts.ANOMALY, mlCounts.NORMAL, ruleCounts.ANOMALY, ruleCounts.NORMAL],
        backgroundColor: ['#a855f7','#3b82f6','#ef4444','#22c55e'], borderRadius: 4, borderWidth: 0 }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color:'#8b8fa8', font:{size:11} }, grid: { color:'#2a2d3a' } },
        y: { ticks: { color:'#8b8fa8', font:{size:11} }, grid: { color:'#2a2d3a' } }
      }
    }
  });

  // Table
  const tbody = document.getElementById('risk-table-body');
  tbody.innerHTML = rows.map(r => `
    <tr onclick="openSessions('${r.user}')">
      <td><strong>${r.user}</strong></td>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="risk-bar-wrap"><div class="risk-bar" style="width:${r.normalized_risk}%;background:${barColor(r.risk_level)}"></div></div>
          <span>${r.normalized_risk}%</span>
        </div>
      </td>
      <td><span class="badge ${r.risk_level}">${r.risk_level}</span></td>
      <td><span class="badge ${r.ml_flag}">${r.ml_flag}</span></td>
      <td><span class="badge ${r.rule_flag}">${r.rule_flag}</span></td>
      <td><span class="badge ${r.final_verdict}">${r.final_verdict}</span></td>
    </tr>
  `).join('');
}

async function loadEvents() {
  const r = await fetch('/api/events');
  const events = await r.json();
  document.getElementById('event-log').innerHTML = events.map(e => `
    <div class="event-row">
      <span class="event-ts">${e.timestamp || '—'}</span>
      <span class="event-user">${e.user}</span>
      <span class="event-action">${e.action}</span>
      <span class="event-source">${e.source}</span>
    </div>
  `).join('');
}

async function openSessions(user) {
  const r = await fetch('/api/sessions/' + user);
  const sessions = await r.json();
  document.getElementById('modal-title').textContent = `Sessions — ${user}`;
  document.getElementById('modal-body').innerHTML = sessions.length === 0
    ? '<p style="color:var(--muted)">No sessions recorded.</p>'
    : sessions.map(s => `
        <div class="session-block">
          <div class="sh">
            <span class="st">${s.session_id}</span>
            <span style="color:var(--muted)">${s.duration_seconds != null ? s.duration_seconds + 's' : 'open'}</span>
          </div>
          <div style="display:flex;gap:16px;margin-bottom:8px;color:var(--muted)">
            <span>Login: ${s.login_time || '—'}</span>
            <span>Logout: ${s.logout_time || 'not seen'}</span>
          </div>
          <div style="display:flex;gap:12px;margin-bottom:8px;font-size:12px">
            <span>Actions: <strong>${s.action_count}</strong></span>
            <span>Sudo: <strong>${s.sudo_count}</strong></span>
            <span>Failed logins: <strong>${s.failed_logins}</strong></span>
            <span>Destructive: <strong>${s.destructive_count}</strong></span>
            ${s.suspicious_sequence ? '<span style="color:#ef4444;font-weight:600">⚠ Suspicious sequence</span>' : ''}
          </div>
          <div class="session-actions">${(s.actions || []).join(' → ')}</div>
        </div>
      `).join('');
  document.getElementById('modal-bg').classList.add('open');
}

function closeModal(e) {
  if (e.target.id === 'modal-bg') document.getElementById('modal-bg').classList.remove('open');
}

async function refresh() {
  await Promise.all([loadStats(), loadRiskTable(), loadEvents()]);
  document.getElementById('last-refresh').textContent =
    'Last refresh: ' + new Date().toLocaleTimeString();
}

refresh();
setInterval(refresh, 30000);   // auto-refresh every 30 seconds
</script>
</body>
</html>
"""

# ── API routes ─────────────────────────────────────────────────────────────────

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


if __name__ == "__main__":
    print("C-PAM Dashboard running at http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)