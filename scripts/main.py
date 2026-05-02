# main.py

import json
import os
import sys
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ingestion import read_auth_logs
from normalization import normalise_linux, normalise_ldap
from risk_engine import get_privilege, calculate_risk, sequence_risk, normalize_score, risk_level
from utils import save_json
from ml_model import run_anomaly_detection
from session_tracker import build_sessions, session_summary
from db import init_db, upsert_users, insert_risk_scores, insert_sessions, insert_events
from threat_patterns import detect_patterns
from insight_engine import run_insights
from db import insert_insights, get_user_insight

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR  = os.path.join(BASE_DIR, "logs")


def load_logs(log_dir: str) -> list:
    logs = []

    linux_path = os.path.join(log_dir, "linux_logs.json")
    ldap_path  = os.path.join(log_dir, "ldap_logs.json")

    if os.path.exists(linux_path):
        with open(linux_path) as f:
            for line in f:
                if line.strip():
                    logs.append(normalise_linux(json.loads(line)))
    else:
        print(f"[WARN] {linux_path} not found — skipping")

    if os.path.exists(ldap_path):
        with open(ldap_path) as f:
            for line in f:
                if line.strip():
                    logs.append(normalise_ldap(json.loads(line)))
    else:
        print(f"[WARN] {ldap_path} not found — skipping")

    real_logs = read_auth_logs(log_dir)
    logs.extend(real_logs)

    return logs


def build_user_index(logs: list) -> dict:
    """Group logs by user once — O(n) instead of O(n²)."""
    index = defaultdict(list)
    for log in logs:
        index[log["user"]].append(log)
    return index


def run_pipeline():
    # 1. Ingest + normalize
    normalised_logs = load_logs(LOG_DIR)
    for log in normalised_logs:
        log["privilege"] = get_privilege(log["action"])
    normalised_logs.sort(key=lambda x: x["timestamp"])

    # 2. Build per-user index (O(n), not O(n²))
    user_index = build_user_index(normalised_logs)
    user_sessions = {user: [log["action"] for log in logs]
                     for user, logs in user_index.items()}
    
    # Phase 2 — Session tracking
    all_sessions    = build_sessions(normalised_logs)
    sess_summary    = session_summary(all_sessions)

    # Merge session summary into user_summary later (already handled below)
    save_json(os.path.join(LOG_DIR, "sessions.json"), all_sessions)

    # 3. ML detection (separate from rule flags)
    ml_results = run_anomaly_detection(user_sessions)
    # Train action-level model
    from ml_model import train_action_model
    train_action_model(user_sessions)

    # 4. Rule-based risk scoring
    raw_scores = {}
    rule_flags = {}

    for user, logs in user_index.items():
        actions = [log["action"] for log in logs]
        score = sum(calculate_risk(log["action"], user, log["privilege"]) for log in logs)
        score += sequence_risk(actions)
        raw_scores[user] = score

        # Rule flag is SEPARATE from ML flag — never overwrites it
        rule_flags[user] = "ANOMALY" if actions.count("login_failed") >= 3 else "NORMAL"

    # 5. Normalize + assemble summary
    user_summary = {}
    for user, logs in user_index.items():
        actions = [log["action"] for log in logs]
        norm = normalize_score(raw_scores[user])
        ml_info = ml_results.get(user, {})

        user_summary[user] = {
            "total_actions"       : len(actions),
            "failed_logins"       : actions.count("login_failed"),
            "sudo_count"          : actions.count("sudo"),
            "destructive_commands": sum(1 for a in actions if "rm -rf" in a),
            "raw_risk_score"      : raw_scores[user],
            "normalized_risk"     : norm,
            "risk_level"          : risk_level(norm),
            "ml_flag"             : ml_info.get("ml_flag", "UNKNOWN"),
            "ml_anomaly_score"    : ml_info.get("anomaly_score", 0),
            "rule_flag"           : rule_flags[user],
            "session_data": sess_summary.get(user, {}),
            # Combined verdict: flagged if EITHER system raises alarm
            "final_verdict"       : "ANOMALY" if (
                ml_info.get("ml_flag") == "ANOMALY" or rule_flags[user] == "ANOMALY"
            ) else "NORMAL",
        }

    # 6. Print summary
    print("\n=== C-PAM Risk Report ===")
    for user, summary in sorted(user_summary.items(),
                                 key=lambda x: x[1]["normalized_risk"], reverse=True):
        print(f"  {user:<20} Risk: {summary['normalized_risk']:>5}% [{summary['risk_level']:<8}]"
              f"  ML: {summary['ml_flag']:<7}  Rule: {summary['rule_flag']:<7}"
              f"  Verdict: {summary['final_verdict']}")

    # 7. Save outputs
    save_json(os.path.join(LOG_DIR, "normalized_logs.json"), normalised_logs)
    save_json(os.path.join(LOG_DIR, "risk_scores.json"),
              {u: s["normalized_risk"] for u, s in user_summary.items()})
    save_json(os.path.join(LOG_DIR, "ml_results.json"), ml_results)
    save_json(os.path.join(LOG_DIR, "user_summary.json"), user_summary)
    print("\n[✓] Output saved to logs/")

    init_db()
    upsert_users(user_summary)
    insert_risk_scores(user_summary)
    insert_sessions(all_sessions)
    insert_events(normalised_logs)
    print("[DB] All data persisted to cpam.db")

    # Phase 5 — Pattern detection + narrative insights
    print("\n[Insight] Running threat pattern detection...")
    all_pattern_data = [
        detect_patterns(user, all_sessions.get(user, []), user_summary.get(user, {}))
        for user in user_summary
    ]

    print("[Insight] Generating LLM narratives via Gemini API...")
    insights = run_insights(all_pattern_data)

    insert_insights(insights, all_pattern_data)
    save_json(os.path.join(LOG_DIR, "insights.json"), insights)

    # Print narratives to terminal
    print("\n=== THREAT NARRATIVES ===")
    for user, data in insights.items():
        if data["pattern_count"] > 0:
            print(f"\n--- {user.upper()} [{data['highest_severity']}] ---")
            print(data["insight"])


if __name__ == "__main__":
    run_pipeline()