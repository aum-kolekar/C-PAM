# session_tracker.py

from datetime import datetime
from collections import defaultdict


def _to_dt(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.min


def build_sessions(normalised_logs: list) -> dict:
    """
    Groups logs per user into discrete login sessions.
    A session starts on login_success or session_open,
    ends on session_close or the next login_success (re-login).

    Returns:
        {
          "alice": [
            {
              "session_id": "alice_1",
              "login_time": "2025-04-30T14:00:00",
              "logout_time": "2025-04-30T14:45:00",
              "duration_seconds": 2700,
              "actions": [...],
              "action_count": 12,
              "sudo_count": 2,
              "failed_logins": 0,
              "destructive_count": 1,
              "actions_per_minute": 0.44,
              "suspicious_sequence": True,
            },
            ...
          ]
        }
    """
    SESSION_START = {"login_success", "session_open"}
    SESSION_END   = {"session_close"}
    DESTRUCTIVE   = {"rm -rf", "dd if=", "mkfs", "shred"}

    # Sort all logs by timestamp globally
    sorted_logs = sorted(normalised_logs, key=lambda x: _to_dt(x["timestamp"]))

    # Group sorted logs by user
    user_logs = defaultdict(list)
    for log in sorted_logs:
        user_logs[log["user"]].append(log)

    all_sessions = {}

    for user, logs in user_logs.items():
        sessions = []
        current_session = None
        session_counter = 0

        for log in logs:
            action = log["action"]
            ts     = log["timestamp"]

            # Start a new session
            if action in SESSION_START:
                # If there's an open session with no logout, close it here
                if current_session is not None:
                    current_session["logout_time"] = ts
                    sessions.append(_finalise(current_session))

                session_counter += 1
                current_session = {
                    "session_id"   : f"{user}_{session_counter}",
                    "login_time"   : ts,
                    "logout_time"  : None,
                    "actions"      : [action],
                }

            elif action in SESSION_END:
                if current_session is not None:
                    current_session["logout_time"] = ts
                    current_session["actions"].append(action)
                    sessions.append(_finalise(current_session))
                    current_session = None

            else:
                # Mid-session action
                if current_session is not None:
                    current_session["actions"].append(action)
                else:
                    # Action with no preceding login — create an implicit session
                    session_counter += 1
                    current_session = {
                        "session_id"  : f"{user}_{session_counter}_implicit",
                        "login_time"  : ts,
                        "logout_time" : None,
                        "actions"     : [action],
                    }

        # Close any session still open at end of log
        if current_session is not None:
            current_session["logout_time"] = None   # logout not seen
            sessions.append(_finalise(current_session))

        all_sessions[user] = sessions

    return all_sessions


def _finalise(session: dict) -> dict:
    """Computes all derived metrics for a completed session."""
    DESTRUCTIVE = ["rm -rf", "dd if=", "mkfs", "shred"]

    actions    = session["actions"]
    login_dt   = _to_dt(session["login_time"])
    logout_dt  = _to_dt(session["logout_time"]) if session["logout_time"] else None

    duration_seconds = (
        int((logout_dt - login_dt).total_seconds())
        if logout_dt and logout_dt > login_dt
        else None
    )

    duration_minutes = duration_seconds / 60 if duration_seconds else None

    sudo_count        = actions.count("sudo")
    failed_logins     = actions.count("login_failed")
    destructive_count = sum(1 for a in actions if any(kw in a for kw in DESTRUCTIVE))
    action_count      = len(actions)

    actions_per_minute = (
        round(action_count / duration_minutes, 2)
        if duration_minutes and duration_minutes > 0
        else None
    )

    # Suspicious sequence: failed logins followed by sudo in same session
    suspicious_sequence = False
    if failed_logins >= 2 and sudo_count > 0:
        action_list = actions
        last_fail   = max((i for i, a in enumerate(action_list) if a == "login_failed"), default=-1)
        first_sudo  = next((i for i, a in enumerate(action_list) if a == "sudo"), -1)
        if first_sudo > last_fail:
            suspicious_sequence = True

    return {
        "session_id"          : session["session_id"],
        "login_time"          : session["login_time"],
        "logout_time"         : session["logout_time"],
        "duration_seconds"    : duration_seconds,
        "actions"             : actions,
        "action_count"        : action_count,
        "sudo_count"          : sudo_count,
        "failed_logins"       : failed_logins,
        "destructive_count"   : destructive_count,
        "actions_per_minute"  : actions_per_minute,
        "suspicious_sequence" : suspicious_sequence,
    }


def session_summary(all_sessions: dict) -> dict:
    """
    Collapses all sessions per user into a single summary row.
    This is what gets stored in the DB and shown on the dashboard.
    """
    summary = {}

    for user, sessions in all_sessions.items():
        total_sessions     = len(sessions)
        total_actions      = sum(s["action_count"] for s in sessions)
        total_sudo         = sum(s["sudo_count"] for s in sessions)
        total_failed       = sum(s["failed_logins"] for s in sessions)
        total_destructive  = sum(s["destructive_count"] for s in sessions)
        any_suspicious     = any(s["suspicious_sequence"] for s in sessions)

        durations = [s["duration_seconds"] for s in sessions if s["duration_seconds"]]
        avg_duration = round(sum(durations) / len(durations), 1) if durations else None

        summary[user] = {
            "total_sessions"      : total_sessions,
            "total_actions"       : total_actions,
            "total_sudo"          : total_sudo,
            "total_failed_logins" : total_failed,
            "total_destructive"   : total_destructive,
            "avg_session_duration": avg_duration,
            "any_suspicious_seq"  : any_suspicious,
        }

    return summary