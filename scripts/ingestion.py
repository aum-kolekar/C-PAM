import os
from parser import parse_auth_log


def read_auth_logs(baseDIR):
    """
    Reads auth.log file and parses it into structured logs
    """

    real_logs = []

    log_path = os.path.join(baseDIR, "auth.log")

    # check if file exists (prevents crash)
    if not os.path.exists(log_path):
        print(f"[WARNING] auth.log not found at {log_path}")
        return real_logs

    try:
        with open(log_path, "r") as f:
            for line in f:
                parsed = parse_auth_log(line)
                if parsed:
                    real_logs.append(parsed)

    except Exception as e:
        print(f"[ERROR] Failed to read auth.log: {e}")
        return real_logs

    return real_logs