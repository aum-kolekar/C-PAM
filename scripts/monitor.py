# monitor.py
# Real-time C-PAM monitor.
# Run with: python monitor.py
# Watches auth.log continuously, scores every new event,
# triggers AI summary instantly for suspicious actions.

import os
import sys
import time
import json
import sqlite3
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from log_parser   import parse_auth_log
from risk_engine  import get_privilege, calculate_risk, sequence_risk, normalize_score, risk_level
from db           import get_connection, init_db

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "logs", "auth.log")

# Actions that trigger an immediate Ollama summary
ALERT_TRIGGERS = {
    "sudo", "session_open", "session_close"
}
DESTRUCTIVE = ["rm -rf", "dd if=", "mkfs", "shred"]

# In-memory session state — rebuilt from DB on startup
user_sessions  = defaultdict(list)   # user -> [actions]
user_raw_score = defaultdict(int)    # user -> cumulative raw score


# ── Ollama call (non-blocking, inline) ────────────────────────────────────────

def get_ai_summary(user: str, action: str, recent_actions: list, score: float) -> str:
    import urllib.request, urllib.error

    recent_str = " → ".join(recent_actions[-10:])
    prompt = (
        f"User '{user}' just performed '{action}'. "
        f"Their recent actions: {recent_str}. "
        f"Current risk score: {score}%. "
        f"In 2 sentences max, tell a SOC analyst what is happening and what to watch for. "
        f"No headers. No bullet points. Be direct."
    )
    payload = json.dumps({
        "model" : "mistral",
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 120}
    }).encode()

    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["response"].strip()
    except Exception as e:
        return f"[Ollama unavailable: {e}]"


# ── DB helpers ────────────────────────────────────────────────────────────────

def store_realtime_event(log: dict, privilege: str, raw_score: int,
                          norm: float, level_str: str):
    conn = get_connection()
    conn.execute("""
        INSERT INTO events (user, action, timestamp, source, privilege)
        VALUES (?, ?, ?, ?, ?)
    """, (log["user"], log["action"], log["timestamp"], log["source"], privilege))
    conn.execute("""
        INSERT OR REPLACE INTO risk_scores
          (user, run_timestamp, raw_score, normalized_risk, risk_level,
           ml_flag, ml_anomaly_score, rule_flag, final_verdict)
        VALUES (?, ?, ?, ?, ?, 'REALTIME', 0.0, 'REALTIME', ?)
        ON CONFLICT(user) DO UPDATE SET
          raw_score        = excluded.raw_score,
          normalized_risk  = excluded.normalized_risk,
          risk_level       = excluded.risk_level,
          run_timestamp    = excluded.run_timestamp,
          final_verdict    = excluded.final_verdict
    """, (log["user"], datetime.now().isoformat(),
          raw_score, norm, level_str,
          level_str if norm >= 50 else "NORMAL"))
    conn.commit()
    conn.close()


def store_alert(user: str, action: str, summary: str, norm: float, level_str: str):
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS realtime_alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user        TEXT,
            action      TEXT,
            summary     TEXT,
            risk_score  REAL,
            risk_level  TEXT,
            timestamp   TEXT
        )
    """)
    conn.execute("""
        INSERT INTO realtime_alerts (user, action, summary, risk_score, risk_level, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user, action, summary, norm, level_str, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_realtime_insight(user: str, summary: str, norm: float):
    """Updates the insights table so the dashboard shows the latest summary."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO insights (user, run_timestamp, insight, pattern_count, highest_severity, patterns_json)
        VALUES (?, ?, ?, 0, 'REALTIME', '[]')
        ON CONFLICT(user) DO UPDATE SET
          insight       = excluded.insight,
          run_timestamp = excluded.run_timestamp,
          highest_severity = CASE
            WHEN excluded.insight != '' THEN 'REALTIME' ELSE highest_severity
          END
    """, (user, datetime.now().isoformat(), summary))
    conn.commit()
    conn.close()


def should_alert(action: str, actions: list) -> bool:
    """Returns True if this action warrants an immediate AI summary."""
    if action in ALERT_TRIGGERS:
        return True
    if any(kw in action for kw in DESTRUCTIVE):
        return True
    if actions.count("login_failed") >= 3:
        return True
    if actions.count("sudo") >= 2:
        return True
    return False


# ── Startup: rebuild state from existing DB ───────────────────────────────────

def rebuild_state_from_db():
    """Load existing user sessions from DB so we don't lose context on restart."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT user, action FROM events ORDER BY timestamp ASC"
    ).fetchall()
    conn.close()

    for row in rows:
        user_sessions[row["user"]].append(row["action"])

    score_rows = conn.execute(
        "SELECT user, raw_score FROM risk_scores"
    ) if False else []  # skip — recalc live

    print(f"[Monitor] Rebuilt state: {len(user_sessions)} users from DB")


# ── Main watch loop ───────────────────────────────────────────────────────────

def watch(log_path: str):
    print(f"[Monitor] Watching {log_path}")
    print(f"[Monitor] Suspicious actions trigger instant AI summary via Ollama")
    print(f"[Monitor] Dashboard auto-updates at http://localhost:5000\n")

    # Seek to end of file — only process NEW lines
    with open(log_path, "r") as f:
        f.seek(0, 2)   # jump to end

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)   # no new line — wait half a second
                continue

            log = parse_auth_log(line)
            if not log:
                continue

            user    = log["user"]
            action  = log["action"]
            ts      = log["timestamp"]

            # Update in-memory session
            user_sessions[user].append(action)
            actions = user_sessions[user]

            # Score this event
            privilege     = get_privilege(action)
            event_score   = calculate_risk(action, user, privilege)
            seq_score     = sequence_risk(actions)
            user_raw_score[user] += event_score
            total_raw     = user_raw_score[user] + seq_score
            norm          = normalize_score(total_raw)
            level_str     = risk_level(norm)

            # Store event + updated risk score
            store_realtime_event(log, privilege, total_raw, norm, level_str)

            # Print to terminal
            flag = "⚠ " if should_alert(action, actions) else "  "
            print(f"{flag}[{ts}] {user:<15} {action:<35} "
                  f"risk: {norm:>5.1f}% [{level_str}]")

            # Trigger AI summary for suspicious actions
            if should_alert(action, actions):
                print(f"   → Generating AI summary for {user}...")
                summary = get_ai_summary(user, action, actions, norm)
                print(f"   → {summary}\n")
                store_alert(user, action, summary, norm, level_str)
                update_realtime_insight(user, summary, norm)


def main():
    init_db()

    # Create alerts table on startup
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS realtime_alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user        TEXT,
            action      TEXT,
            summary     TEXT,
            risk_score  REAL,
            risk_level  TEXT,
            timestamp   TEXT
        )
    """)
    conn.commit()
    conn.close()

    rebuild_state_from_db()

    if not os.path.exists(LOG_PATH):
        print(f"[ERROR] auth.log not found at {LOG_PATH}")
        print("Set LOG_PATH in monitor.py to point to your auth.log")
        sys.exit(1)

    watch(LOG_PATH)


if __name__ == "__main__":
    main()