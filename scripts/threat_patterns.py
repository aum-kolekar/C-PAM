# threat_patterns.py
# Detects named threat patterns from session data.
# Returns structured findings — not scores, named patterns with evidence.

from datetime import datetime
from typing import Optional


def _to_dt(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _minutes_between(ts1: Optional[str], ts2: Optional[str]) -> Optional[float]:
    a, b = _to_dt(ts1), _to_dt(ts2)
    if a and b:
        return abs((b - a).total_seconds() / 60)
    return None


DESTRUCTIVE = ["rm -rf", "dd if=", "mkfs", "shred", "wipefs"]
RECON_CMDS  = ["whoami", "id", "uname", "cat /etc/passwd", "cat /etc/shadow",
               "netstat", "ss -", "ps aux", "ls /home", "find /"]
EXFIL_CMDS  = ["scp ", "rsync ", "curl ", "wget ", "nc ", "tar "]


def detect_patterns(user: str, sessions: list, user_summary: dict) -> dict:
    """
    Runs all pattern detectors against a user's session list.

    Returns:
        {
          "user": str,
          "patterns_detected": [
              {
                "name": str,           # e.g. "brute_force_then_escalation"
                "severity": str,       # CRITICAL / HIGH / MEDIUM / LOW
                "description": str,    # one-line human label
                "evidence": [...],     # list of specific supporting facts
                "session_ids": [...],  # which sessions
              }
          ],
          "timeline": [...],           # flat chronological event list for LLM context
          "session_count": int,
          "risk_context": dict,        # from user_summary
        }
    """
    findings = []

    findings += _detect_brute_force(sessions)
    findings += _detect_privilege_escalation(sessions)
    findings += _detect_brute_then_escalation(sessions)
    findings += _detect_destructive_activity(sessions)
    findings += _detect_recon(sessions)
    findings += _detect_exfiltration(sessions)
    findings += _detect_off_hours(sessions)
    findings += _detect_rapid_fire(sessions)

    timeline = _build_timeline(sessions)

    return {
        "user"              : user,
        "patterns_detected" : findings,
        "timeline"          : timeline,
        "session_count"     : len(sessions),
        "risk_context"      : {
            "normalized_risk" : user_summary.get("normalized_risk"),
            "risk_level"      : user_summary.get("risk_level"),
            "ml_flag"         : user_summary.get("ml_flag"),
            "ml_anomaly_score": user_summary.get("ml_anomaly_score"),
            "rule_flag"       : user_summary.get("rule_flag"),
            "final_verdict"   : user_summary.get("final_verdict"),
        }
    }


# ── Individual detectors ──────────────────────────────────────────────────────

def _detect_brute_force(sessions: list) -> list:
    findings = []
    for s in sessions:
        fails = s["actions"].count("login_failed")
        if fails >= 3:
            findings.append({
                "name"       : "brute_force_attempt",
                "severity"   : "HIGH" if fails < 6 else "CRITICAL",
                "description": f"Repeated login failures ({fails} attempts) in one session",
                "evidence"   : [
                    f"{fails} failed login attempts in session {s['session_id']}",
                    f"Session started at {s['login_time']}",
                ],
                "session_ids": [s["session_id"]],
            })
    return findings


def _detect_privilege_escalation(sessions: list) -> list:
    findings = []
    for s in sessions:
        if s["sudo_count"] > 0:
            severity = "CRITICAL" if s["sudo_count"] >= 3 else "HIGH"
            findings.append({
                "name"       : "privilege_escalation",
                "severity"   : severity,
                "description": f"Privilege escalation via sudo ({s['sudo_count']} times)",
                "evidence"   : [
                    f"sudo used {s['sudo_count']} time(s) in session {s['session_id']}",
                    f"Session duration: {s.get('duration_seconds', 'unknown')}s",
                ],
                "session_ids": [s["session_id"]],
            })
    return findings


def _detect_brute_then_escalation(sessions: list) -> list:
    """The most important compound pattern — failed logins followed by sudo in same session."""
    findings = []
    for s in sessions:
        if not s.get("suspicious_sequence"):
            continue
        actions   = s["actions"]
        fails     = actions.count("login_failed")
        last_fail = max((i for i, a in enumerate(actions) if a == "login_failed"), default=-1)
        first_sudo= next((i for i, a in enumerate(actions) if a == "sudo"), -1)
        gap_actions = first_sudo - last_fail

        findings.append({
            "name"       : "brute_force_then_escalation",
            "severity"   : "CRITICAL",
            "description": "Brute-force attempt followed by successful privilege escalation",
            "evidence"   : [
                f"{fails} failed logins, then sudo after {gap_actions} action(s)",
                f"Session {s['session_id']} at {s['login_time']}",
                "Classic credential-stuffing-to-escalation attack chain",
            ],
            "session_ids": [s["session_id"]],
        })
    return findings


def _detect_destructive_activity(sessions: list) -> list:
    findings = []
    for s in sessions:
        hits = [a for a in s["actions"] if any(kw in a for kw in DESTRUCTIVE)]
        if hits:
            findings.append({
                "name"       : "destructive_command_execution",
                "severity"   : "CRITICAL",
                "description": f"Destructive commands executed ({len(hits)} instance(s))",
                "evidence"   : [f"Command: `{cmd}`" for cmd in hits[:5]],
                "session_ids": [s["session_id"]],
            })
    return findings


def _detect_recon(sessions: list) -> list:
    findings = []
    for s in sessions:
        hits = [a for a in s["actions"] if any(kw in a for kw in RECON_CMDS)]
        if len(hits) >= 3:
            findings.append({
                "name"       : "reconnaissance_activity",
                "severity"   : "MEDIUM",
                "description": f"Multiple reconnaissance commands ({len(hits)} detected)",
                "evidence"   : [f"`{cmd}`" for cmd in hits[:5]],
                "session_ids": [s["session_id"]],
            })
    return findings


def _detect_exfiltration(sessions: list) -> list:
    findings = []
    for s in sessions:
        hits = [a for a in s["actions"] if any(kw in a for kw in EXFIL_CMDS)]
        if hits:
            findings.append({
                "name"       : "potential_data_exfiltration",
                "severity"   : "HIGH",
                "description": f"Commands consistent with data transfer/exfiltration ({len(hits)} instance(s))",
                "evidence"   : [f"`{cmd}`" for cmd in hits[:5]],
                "session_ids": [s["session_id"]],
            })
    return findings


def _detect_off_hours(sessions: list) -> list:
    """Flags sessions starting outside 07:00–20:00."""
    findings = []
    for s in sessions:
        dt = _to_dt(s.get("login_time"))
        if dt and (dt.hour < 7 or dt.hour >= 20):
            findings.append({
                "name"       : "off_hours_access",
                "severity"   : "MEDIUM",
                "description": f"Session initiated outside business hours at {dt.strftime('%H:%M')}",
                "evidence"   : [
                    f"Login at {s['login_time']}",
                    f"Session ID: {s['session_id']}",
                ],
                "session_ids": [s["session_id"]],
            })
    return findings


def _detect_rapid_fire(sessions: list) -> list:
    """Flags sessions with unusually high actions-per-minute — scripted/automated behavior."""
    findings = []
    for s in sessions:
        apm = s.get("actions_per_minute")
        if apm and apm > 30:
            findings.append({
                "name"       : "automated_or_scripted_behavior",
                "severity"   : "HIGH",
                "description": f"Abnormally high action rate ({apm} actions/min) — possible script",
                "evidence"   : [
                    f"{s['action_count']} actions in {s.get('duration_seconds', '?')}s",
                    f"Session {s['session_id']}",
                ],
                "session_ids": [s["session_id"]],
            })
    return findings


def _build_timeline(sessions: list) -> list:
    """Flat chronological list of significant events for LLM context."""
    events = []
    for s in sessions:
        for action in s["actions"]:
            events.append({
                "session_id": s["session_id"],
                "login_time": s["login_time"],
                "action"    : action,
            })
    return events[:60]   # cap at 60 events — enough context, not too many tokens