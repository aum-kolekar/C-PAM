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