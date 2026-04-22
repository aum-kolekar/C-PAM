import json

def normalise_linux(log):
    return {
        "user": log["user"],
        "action": log["action"],
        "timestamp": log["time"],
        "source": "linux"
    }

def normalise_ldap(log):
    action_map = {
        "success": "login_success",
        "failed": "login_failed"
    }
    return {
        "user": log["uid"],
        "action": action_map.get(log["auth"]),
        "timestamp": log["time"],
        "source": "ldap"
    }

normalised_logs = []

with open('linux_logs.json') as f:
    for line in f:
        if line.strip():
            log = json.loads(line)
            normalised_logs.append(normalise_linux(log))

with open('ldap_logs.json') as f:
    for line in f:
        if line.strip():
            log = json.loads(line)
            normalised_logs.append(normalise_ldap(log))

for logs in normalised_logs:
    print(logs)


normalised_logs.sort(key=lambda x: x["timestamp"])

def calculate_risk(action, user):
    score = 0
    
    if "admin" in user:
        score += 20   # privilege weight
    
    if action == "sudo":
        score += 50
    if "rm -rf" in action:
        score += 30
    if action == "login_failed":
        score += 10
    
    return score

user_sessions = {}

for log in normalised_logs:
    user = log["user"]
    
    if user not in user_sessions:
        user_sessions[user] = []
    
    user_sessions[user].append(log["action"])


final_risk = {}

for user, actions in user_sessions.items():
    score = 0
    
    for action in actions:
        score += calculate_risk(action, user)
    
    final_risk[user] = score

for user, score in final_risk.items():
    print(user, "→ FINAL RISK:", score)

import json

# Save normalized logs
with open("normalized_logs.json", "w") as f:
    json.dump(normalised_logs, f, indent=4)

# Save final risk
with open("risk_scores.json", "w") as f:
    json.dump(final_risk, f, indent=4)