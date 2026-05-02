# Real-time C-PAM monitor.
# Run with: python monitor.py

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
from ml_model     import score_action

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = "/var/log/auth.log"

ALERT_TRIGGERS = {"sudo", "session_open", "session_close"}
DESTRUCTIVE = ["rm -rf", "dd if=", "mkfs", "shred"]

user_sessions  = defaultdict(list)
user_raw_score = defaultdict(int)


# ── Ollama ─────────────────────────────────────────────

def get_ai_summary(user: str, action: str, recent_actions: list, score: float) -> str:
    import urllib.request

    recent_str = " → ".join(recent_actions[-10:])
    prompt = (
        f"User '{user}' just performed '{action}'. "
        f"Their recent actions: {recent_str}. "
        f"Current risk score: {score}%. "
        f"In 2 sentences max, tell a SOC analyst what is happening."
    )

    payload = json.dumps({
        "model": "mistral",
        "prompt": prompt,
        "stream": False
    }).encode()

    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["response"].strip()
    except Exception as e:
        return f"[Ollama unavailable: {e}]"


# ── UPDATED DB FUNCTION ────────────────────────────────

def store_realtime_event(log: dict, privilege: str, raw_score: int,
                          norm: float, level_str: str, action_ml: dict = None):
    conn = get_connection()

    # Add ML columns if not present
    try:
        conn.execute("ALTER TABLE events ADD COLUMN action_ml_flag TEXT")
        conn.execute("ALTER TABLE events ADD COLUMN action_ml_score REAL")
        conn.commit()
    except Exception:
        pass

    conn.execute("""
        INSERT INTO events (user, action, timestamp, source, privilege,
                           action_ml_flag, action_ml_score)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        log["user"], log["action"], log["timestamp"],
        log["source"], privilege,
        action_ml.get("ml_flag") if action_ml else None,
        action_ml.get("anomaly_score") if action_ml else None,
    ))

    conn.execute("""
        INSERT OR REPLACE INTO risk_scores
          (user, run_timestamp, raw_score, normalized_risk, risk_level,
           ml_flag, ml_anomaly_score, rule_flag, final_verdict)
        VALUES (?, ?, ?, ?, ?, 'REALTIME', 0.0, 'REALTIME', ?)
        ON CONFLICT(user) DO UPDATE SET
          raw_score       = excluded.raw_score,
          normalized_risk = excluded.normalized_risk,
          risk_level      = excluded.risk_level,
          run_timestamp   = excluded.run_timestamp,
          final_verdict   = excluded.final_verdict
    """, (
        log["user"], datetime.now().isoformat(),
        raw_score, norm, level_str,
        level_str if norm >= 50 else "NORMAL"
    ))

    conn.commit()
    conn.close()


# ── Alerts ─────────────────────────────────────────────

def store_alert(user, action, summary, norm, level_str):
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS realtime_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            summary TEXT,
            risk_score REAL,
            risk_level TEXT,
            timestamp TEXT
        )
    """)
    conn.execute("""
        INSERT INTO realtime_alerts (user, action, summary, risk_score, risk_level, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user, action, summary, norm, level_str, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def update_realtime_insight(user, summary, norm):
    conn = get_connection()
    conn.execute("""
        INSERT INTO insights (user, run_timestamp, insight, pattern_count, highest_severity, patterns_json)
        VALUES (?, ?, ?, 0, 'REALTIME', '[]')
        ON CONFLICT(user) DO UPDATE SET
          insight = excluded.insight,
          run_timestamp = excluded.run_timestamp
    """, (user, datetime.now().isoformat(), summary))
    conn.commit()
    conn.close()


def should_alert(action, actions):
    if action in ALERT_TRIGGERS:
        return True
    if any(kw in action for kw in DESTRUCTIVE):
        return True
    if actions.count("login_failed") >= 3:
        return True
    if actions.count("sudo") >= 2:
        return True
    return False


# ── WATCH LOOP (UPDATED) ───────────────────────────────

def watch(log_path: str):
    print(f"[Monitor] Watching {log_path}\n")

    with open(log_path, "r") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            log = parse_auth_log(line)
            if not log:
                continue

            user   = log["user"]
            action = log["action"]
            ts     = log["timestamp"]

            user_sessions[user].append(action)
            actions = user_sessions[user]

            privilege   = get_privilege(action)
            event_score = calculate_risk(action, user, privilege)
            seq_score   = sequence_risk(actions)

            user_raw_score[user] += event_score
            total_raw = user_raw_score[user] + seq_score
            norm      = normalize_score(total_raw)
            level_str = risk_level(norm)

            # 🔥 NEW: Action-level ML
            action_ml = score_action(action, list(actions[:-1]))

            # Store with ML
            store_realtime_event(log, privilege, total_raw, norm, level_str, action_ml)

            # Terminal output
            ml_tag = f"[ML:{action_ml['ml_flag']}:{action_ml['confidence']}]" \
                     if action_ml['ml_flag'] == "ANOMALY" else ""

            flag = "⚠ " if (
                should_alert(action, actions) or
                action_ml['ml_flag'] == "ANOMALY"
            ) else "  "

            print(f"{flag}[{ts}] {user:<15} {action:<35} "
                  f"risk: {norm:>5.1f}% [{level_str}] {ml_tag}")

            # 🚨 ALERT condition (rule OR ML)
            if should_alert(action, actions) or (
                action_ml['ml_flag'] == "ANOMALY" and
                action_ml['confidence'] in ("HIGH", "MEDIUM")
            ):
                print(f"   → Generating AI summary for {user}...")
                summary = get_ai_summary(user, action, actions, norm)
                print(f"   → {summary}\n")

                store_alert(user, action, summary, norm, level_str)
                update_realtime_insight(user, summary, norm)


# ── MAIN ──────────────────────────────────────────────

def main():
    init_db()
    if not os.path.exists(LOG_PATH):
        print(f"[ERROR] auth.log not found at {LOG_PATH}")
        sys.exit(1)

    watch(LOG_PATH)


if __name__ == "__main__":
    main()