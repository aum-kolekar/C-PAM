import json
import os
import sys

# fix import path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ingestion import read_auth_logs
from normalization import normalise_linux, normalise_ldap
from risk_engine import get_privilege, calculate_risk, sequence_risk
from utils import save_json

# base project directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# logs directory
LOG_DIR = os.path.join(BASE_DIR, "logs")

# ingest real logs
real_logs = read_auth_logs(LOG_DIR)

normalised_logs = []

# linux logs
with open(os.path.join(LOG_DIR, 'linux_logs.json')) as f:
    for line in f:
        if line.strip():
            log = json.loads(line)
            normalised_logs.append(normalise_linux(log))

# ldap logs
with open(os.path.join(LOG_DIR, 'ldap_logs.json')) as f:
    for line in f:
        if line.strip():
            log = json.loads(line)
            normalised_logs.append(normalise_ldap(log))

# add real logs
normalised_logs.extend(real_logs)

# add privilege
for log in normalised_logs:
    log["privilege"] = get_privilege(log["action"])

# sort logs
normalised_logs.sort(key=lambda x: x["timestamp"])

# build user sessions
user_sessions = {}
for log in normalised_logs:
    user_sessions.setdefault(log["user"], []).append(log["action"])

# calculate risk
final_risk = {}

for user, actions in user_sessions.items():
    score = 0

    for log in normalised_logs:
        if log["user"] == user:
            score += calculate_risk(
                log["action"],
                user,
                log["privilege"]
            )

    score += sequence_risk(actions)
    final_risk[user] = score

# output
for user, score in final_risk.items():
    print(user, "-> FINAL RISK:", score)

# save output
save_json(os.path.join(LOG_DIR, "normalized_logs.json"), normalised_logs)
save_json(os.path.join(LOG_DIR, "risk_scores.json"), final_risk)