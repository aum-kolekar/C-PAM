# ingestion.py

import os
from log_parser import parse_auth_log   # renamed from parser.py


def read_auth_logs(baseDIR: str) -> list:
    real_logs = []
    log_path = os.path.join(baseDIR, "auth.log")

    if not os.path.exists(log_path):
        print(f"[WARNING] auth.log not found at {log_path}")
        return real_logs

    try:
        with open(log_path, "r") as f:
            for line in f:
                parsed = parse_auth_log(line)
                if parsed:
                    real_logs.append(parsed)
        print(f"[INFO] Parsed {len(real_logs)} entries from auth.log")
    except Exception as e:
        print(f"[ERROR] Failed to read auth.log: {e}")

    print(f"[INFO] Total logs loaded: {len(real_logs)}")
    return real_logs