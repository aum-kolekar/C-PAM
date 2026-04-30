import re

def parse_auth_log(line):
    if "Accepted password" in line:
        user = re.search(r"for (\w+)", line)
        if user:
            return {
                "user": user.group(1),
                "action": "login_success",
                "timestamp": line[:15],
                "source": "auth_log"
            }

    if "Failed password" in line:
        user = re.search(r"for (\w+)", line)
        if user:
            return {
                "user": user.group(1),
                "action": "login_failed",
                "timestamp": line[:15],
                "source": "auth_log"
            }

    if "sudo:" in line:
        user = re.search(r"sudo:\s+(\w+)", line)
        cmd = re.search(r"COMMAND=(.*)", line)
        if user and cmd:
            return {
                "user": user.group(1),
                "action": cmd.group(1).strip(),
                "timestamp": line[:15],
                "source": "auth_log"
            }

    return None



# log_parser.py

import re
from datetime import datetime

# auth.log has no year — we assume current year.
# In production you'd infer year from log rotation.
CURRENT_YEAR = datetime.now().year


def _parse_timestamp(line: str) -> str:
    """
    Converts 'Apr 30 14:23:01' → ISO format '2025-04-30T14:23:01'
    Returns None if parsing fails.
    """
    raw = line[:15].strip()
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {raw}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return None


def parse_auth_log(line: str) -> dict | None:
    ts = _parse_timestamp(line)
    if not ts:
        return None

    if "Accepted password" in line or "Accepted publickey" in line:
        user = re.search(r"for (\w+) from", line)
        if user:
            return {
                "user"     : user.group(1),
                "action"   : "login_success",
                "timestamp": ts,
                "source"   : "auth_log",
            }

    if "Failed password" in line:
        user = re.search(r"for (?:invalid user )?(\w+) from", line)
        if user:
            return {
                "user"     : user.group(1),
                "action"   : "login_failed",
                "timestamp": ts,
                "source"   : "auth_log",
            }

    if "sudo:" in line and "COMMAND=" in line:
        user = re.search(r"sudo:\s+(\w+)\s*:", line)
        cmd  = re.search(r"COMMAND=(.*)", line)
        if user and cmd:
            return {
                "user"     : user.group(1),
                "action"   : cmd.group(1).strip(),
                "timestamp": ts,
                "source"   : "auth_log",
            }

    if "session opened" in line:
        user = re.search(r"for user (\w+)", line)
        if user:
            return {
                "user"     : user.group(1),
                "action"   : "session_open",
                "timestamp": ts,
                "source"   : "auth_log",
            }

    if "session closed" in line:
        user = re.search(r"for user (\w+)", line)
        if user:
            return {
                "user"     : user.group(1),
                "action"   : "session_close",
                "timestamp": ts,
                "source"   : "auth_log",
            }

    return None