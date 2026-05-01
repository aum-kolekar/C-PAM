# db.py

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpam.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # lets you access columns by name
    return conn


def init_db():
    """Creates all tables if they don't exist. Safe to call on every run."""
    conn = get_connection()
    c = conn.cursor()

    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user            TEXT PRIMARY KEY,
            first_seen      TEXT,
            last_seen       TEXT
        );

        CREATE TABLE IF NOT EXISTS risk_scores (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user            TEXT NOT NULL,
            run_timestamp   TEXT NOT NULL,
            raw_score       REAL,
            normalized_risk REAL,
            risk_level      TEXT,
            ml_flag         TEXT,
            ml_anomaly_score REAL,
            rule_flag       TEXT,
            final_verdict   TEXT,
            FOREIGN KEY (user) REFERENCES users(user)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id          TEXT UNIQUE,
            user                TEXT NOT NULL,
            login_time          TEXT,
            logout_time         TEXT,
            duration_seconds    INTEGER,
            action_count        INTEGER,
            sudo_count          INTEGER,
            failed_logins       INTEGER,
            destructive_count   INTEGER,
            actions_per_minute  REAL,
            suspicious_sequence INTEGER,
            actions_json        TEXT,
            FOREIGN KEY (user) REFERENCES users(user)
        );

        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user        TEXT NOT NULL,
            action      TEXT,
            timestamp   TEXT,
            source      TEXT,
            privilege   TEXT,
            FOREIGN KEY (user) REFERENCES users(user)
        );
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Initialized at {DB_PATH}")


def upsert_users(user_summary: dict):
    conn = get_connection()
    c    = conn.cursor()
    now  = datetime.now().isoformat()

    for user in user_summary:
        c.execute("""
            INSERT INTO users (user, first_seen, last_seen)
            VALUES (?, ?, ?)
            ON CONFLICT(user) DO UPDATE SET last_seen=excluded.last_seen
        """, (user, now, now))

    conn.commit()
    conn.close()


def insert_risk_scores(user_summary: dict):
    conn = get_connection()
    c    = conn.cursor()
    now  = datetime.now().isoformat()

    for user, data in user_summary.items():
        c.execute("""
            INSERT INTO risk_scores
              (user, run_timestamp, raw_score, normalized_risk, risk_level,
               ml_flag, ml_anomaly_score, rule_flag, final_verdict)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user, now,
            data.get("raw_risk_score"),
            data.get("normalized_risk"),
            data.get("risk_level"),
            data.get("ml_flag"),
            data.get("ml_anomaly_score"),
            data.get("rule_flag"),
            data.get("final_verdict"),
        ))

    conn.commit()
    conn.close()


def insert_sessions(all_sessions: dict):
    conn = get_connection()
    c    = conn.cursor()

    for user, sessions in all_sessions.items():
        for s in sessions:
            c.execute("""
                INSERT OR IGNORE INTO sessions
                  (session_id, user, login_time, logout_time, duration_seconds,
                   action_count, sudo_count, failed_logins, destructive_count,
                   actions_per_minute, suspicious_sequence, actions_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                s["session_id"], user,
                s["login_time"], s["logout_time"],
                s["duration_seconds"], s["action_count"],
                s["sudo_count"], s["failed_logins"],
                s["destructive_count"], s["actions_per_minute"],
                int(s["suspicious_sequence"]),
                json.dumps(s["actions"]),
            ))

    conn.commit()
    conn.close()


def insert_events(normalised_logs: list):
    conn = get_connection()
    c    = conn.cursor()

    for log in normalised_logs:
        c.execute("""
            INSERT INTO events (user, action, timestamp, source, privilege)
            VALUES (?, ?, ?, ?, ?)
        """, (
            log.get("user"),
            log.get("action"),
            log.get("timestamp"),
            log.get("source"),
            log.get("privilege"),
        ))

    conn.commit()
    conn.close()


# --- Query helpers (used by the dashboard API) ---

def get_all_risk_scores() -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT r.*, u.first_seen
        FROM risk_scores r
        JOIN users u ON r.user = u.user
        ORDER BY r.normalized_risk DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_sessions(user: str) -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM sessions WHERE user = ? ORDER BY login_time DESC
    """, (user,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        row = dict(r)
        row["actions"] = json.loads(row["actions_json"] or "[]")
        result.append(row)
    return result


def get_recent_events(limit: int = 200) -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM events ORDER BY timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_dashboard_stats() -> dict:
    conn = get_connection()
    c    = conn.cursor()

    total_users    = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    critical_users = c.execute(
        "SELECT COUNT(DISTINCT user) FROM risk_scores WHERE risk_level='CRITICAL'"
    ).fetchone()[0]
    anomaly_users  = c.execute(
        "SELECT COUNT(DISTINCT user) FROM risk_scores WHERE final_verdict='ANOMALY'"
    ).fetchone()[0]
    total_events   = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    suspicious_sessions = c.execute(
        "SELECT COUNT(*) FROM sessions WHERE suspicious_sequence=1"
    ).fetchone()[0]

    conn.close()
    return {
        "total_users"         : total_users,
        "critical_users"      : critical_users,
        "anomaly_users"       : anomaly_users,
        "total_events"        : total_events,
        "suspicious_sessions" : suspicious_sessions,
    }