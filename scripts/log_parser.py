# log_parser.py

import re
from datetime import datetime


def _parse_timestamp(line: str) -> str:
    """
    Handles modern ISO format: 2026-04-26T05:29:41.267782+00:00
    """
    match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
    if match:
        try:
            dt = datetime.fromisoformat(match.group(1))
            return dt.isoformat()
        except ValueError:
            pass
    return datetime.now().isoformat()


def parse_auth_log(line: str) -> dict | None:
    ts = _parse_timestamp(line)

    # SSH successful login
    if "Accepted password" in line or "Accepted publickey" in line:
        user = re.search(r'for (\w+) from', line)
        if user:
            return {"user": user.group(1), "action": "login_success",
                    "timestamp": ts, "source": "auth_log"}

    # SSH failed login
    if "Failed password" in line:
        user = re.search(r'for (?:invalid user )?(\w+) from', line)
        if user:
            return {"user": user.group(1), "action": "login_failed",
                    "timestamp": ts, "source": "auth_log"}

    # sudo command
    if "sudo:" in line and "COMMAND=" in line:
        user = re.search(r'sudo:\s+(\w+)\s*:', line)
        cmd  = re.search(r'COMMAND=(.*)', line)
        if user and cmd:
            return {"user": user.group(1), "action": cmd.group(1).strip(),
                    "timestamp": ts, "source": "auth_log"}

    # session opened — covers gdm, sshd, cron, su
    if "session opened for user" in line:
        user = re.search(r'session opened for user (\w+)', line)
        # skip CRON root sessions — noise
        if user and not ("CRON" in line and user.group(1) == "root"):
            return {"user": user.group(1), "action": "session_open",
                    "timestamp": ts, "source": "auth_log"}

    # session closed
    if "session closed for user" in line:
        user = re.search(r'session closed for user (\w+)', line)
        if user and not ("CRON" in line and user.group(1) == "root"):
            return {"user": user.group(1), "action": "session_close",
                    "timestamp": ts, "source": "auth_log"}

    # su authentication
    if "su:" in line and "Successful su" in line:
        user = re.search(r'for (\w+) by', line)
        if user:
            return {"user": user.group(1), "action": "su_success",
                    "timestamp": ts, "source": "auth_log"}

    # GDM / PAM login
    if "gdm-password" in line and "session opened" in line:
        user = re.search(r'session opened for user (\w+)', line)
        if user:
            return {"user": user.group(1), "action": "login_success",
                    "timestamp": ts, "source": "auth_log"}

    # pam authentication failure
    if "pam_unix" in line and "authentication failure" in line:
        user = re.search(r'user=(\w+)', line)
        if user:
            return {"user": user.group(1), "action": "login_failed",
                    "timestamp": ts, "source": "auth_log"}

    return None