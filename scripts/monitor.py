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
            "http://192.168.56.1:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["response"].strip()
    except Exception as e:
        return f"[Ollama unavailable: {e}]"


def update_realtime_session(user: str, action: str, ts: str,
                             actions: list, session_counter: dict):
    """
    Maintains a live session in the sessions table.
    Creates a new session on login, updates it on every action,
    closes it on logout.
    """
    conn = get_connection()

    SESSION_START = {"login_success", "session_open"}
    SESSION_END   = {"session_close"}
    DESTRUCTIVE   = ["rm -rf", "dd if=", "mkfs", "shred"]

    # Get or create session ID for this user
    if action in SESSION_START:
        session_counter[user] = session_counter.get(user, 0) + 1

    session_id = f"{user}_rt_{session_counter.get(user, 1)}"

    # Compute session metrics from current actions
    sudo_count        = actions.count("sudo")
    failed_logins     = actions.count("login_failed")
    destructive_count = sum(1 for a in actions if any(kw in a for kw in DESTRUCTIVE))
    action_count      = len(actions)

    # Detect suspicious sequence
    suspicious = False
    if failed_logins >= 2 and sudo_count > 0:
        last_fail  = max((i for i, a in enumerate(actions) if a == "login_failed"), default=-1)
        first_sudo = next((i for i, a in enumerate(actions) if a == "sudo"), -1)
        if first_sudo > last_fail:
            suspicious = True

    # Check if session row exists
    existing = conn.execute(
        "SELECT id FROM sessions WHERE session_id = ?", (session_id,)
    ).fetchone()

    if existing:
        # Update existing session
        conn.execute("""
            UPDATE sessions SET
                action_count        = ?,
                sudo_count          = ?,
                failed_logins       = ?,
                destructive_count   = ?,
                suspicious_sequence = ?,
                actions_json        = ?,
                logout_time         = CASE WHEN ? = 'session_close' THEN ? ELSE logout_time END
            WHERE session_id = ?
        """, (
            action_count, sudo_count, failed_logins,
            destructive_count, int(suspicious),
            json.dumps(actions),
            action, ts,
            session_id
        ))
    else:
        # Insert new session
        conn.execute("""
            INSERT INTO sessions
              (session_id, user, login_time, logout_time, duration_seconds,
               action_count, sudo_count, failed_logins, destructive_count,
               actions_per_minute, suspicious_sequence, actions_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id, user, ts, None, None,
            action_count, sudo_count, failed_logins,
            destructive_count, None, int(suspicious),
            json.dumps(actions),
        ))

    # Update duration if session is closing
    if action in SESSION_END:
        conn.execute("""
            UPDATE sessions SET logout_time = ?
            WHERE session_id = ?
        """, (ts, session_id))

    conn.commit()
    conn.close()

# ── UPDATED DB FUNCTION ────────────────────────────────

def store_realtime_event(log: dict, privilege: str, raw_score: int,
                          norm: float, level_str: str, action_ml: dict = None):
    conn = get_connection()

    # Add action ML columns if they don't exist yet
    try:
        conn.execute("ALTER TABLE events ADD COLUMN action_ml_flag TEXT")
        conn.execute("ALTER TABLE events ADD COLUMN action_ml_score REAL")
        conn.commit()
    except Exception:
        pass

    # Insert the event
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

    # Update risk score — delete old row then insert fresh
    conn.execute("DELETE FROM risk_scores WHERE user = ?", (log["user"],))
    conn.execute("""
        INSERT INTO risk_scores
          (user, run_timestamp, raw_score, normalized_risk, risk_level,
           ml_flag, ml_anomaly_score, rule_flag, final_verdict)
        VALUES (?, ?, ?, ?, ?, 'REALTIME', 0.0, 'REALTIME', ?)
    """, (
        log["user"],
        datetime.now().isoformat(),
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


def update_realtime_insight(user: str, summary: str, norm: float):
    conn = get_connection()
    # Delete old insight then insert fresh
    conn.execute("DELETE FROM insights WHERE user = ?", (user,))
    conn.execute("""
        INSERT INTO insights (user, run_timestamp, insight, pattern_count, 
                              highest_severity, patterns_json)
        VALUES (?, ?, ?, 0, 'REALTIME', '[]')
    """, (user, datetime.now().isoformat(), summary))
    conn.commit()
    conn.close()


def should_alert(action: str, actions: list, norm: float,
                 action_ml: dict = None) -> bool:
    """Only alert if risk is HIGH/CRITICAL or ML flags it as anomaly."""

    # Must meet minimum risk threshold
    if norm < 40:
        return False

    # Destructive command — always alert regardless
    if any(kw in action for kw in DESTRUCTIVE):
        return True

    # ML flagged this specific action with high confidence
    if action_ml and action_ml.get("ml_flag") == "ANOMALY" \
            and action_ml.get("confidence") in ("HIGH", "MEDIUM"):
        return True

    # Brute force threshold
    if actions.count("login_failed") >= 3:
        return True

    # Privilege escalation after failures
    if action == "sudo" and actions.count("login_failed") >= 2:
        return True

    return False


# ── WATCH LOOP (UPDATED) ───────────────────────────────

def watch(log_path: str):
    print(f"[Monitor] Watching {log_path}\n")
    print(f"[Monitor] Suspicious actions trigger instant AI summary via Ollama")
    print(f"[Monitor] Dashboard auto-updates at http://<vm_ip>:5000\n")

    session_counter = {}   # tracks session number per user

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

            #  NEW: Action-level ML
            action_ml = score_action(action, list(actions[:-1]))

            # Store with ML
            store_realtime_event(log, privilege, total_raw, norm, level_str, action_ml)

            # Update live session in DB
            update_realtime_session(user, action, ts, list(actions), session_counter)
            # Terminal output
            ml_tag = f"[ML:{action_ml['ml_flag']}:{action_ml['confidence']}]" \
                     if action_ml['ml_flag'] == "ANOMALY" else ""

            flag = "⚠ " if should_alert(action, actions, norm, action_ml) else "  "

            print(f"{flag}[{ts}] {user:<15} {action:<35} "
                  f"risk: {norm:>5.1f}% [{level_str}] {ml_tag}")

            #  ALERT condition (rule OR ML)
            if should_alert(action, actions, norm, action_ml):
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