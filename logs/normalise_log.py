import json
import os
import re

baseDIR = os.path.expanduser("~/cpam/C-PAM/")
LOG_DIR = os.path.dirname(os.path.abspath(__file__))

def get_privilege(action):
    if "sudo" in action or "su" in action:
        return "elevated"
    elif "rm -rf" in action or "dd" in action:
        return "high"
    elif "chmod" in action or "chown" in action:
        return "elevated"
    else:
        return "normal"

def parse_auth_log(line):
    # Login success
    if "Accepted password" in line:
        user = re.search(r"for (\w+)", line)
        if user:
            return {
                "user": user.group(1),
                "action": "login_success",
                "timestamp": line[:15],
                "source": "auth_log"
            }

    # Login failure
    if "Failed password" in line:
        user = re.search(r"for (\w+)", line)
        if user:
            return {
                "user": user.group(1),
                "action": "login_failed",
                "timestamp": line[:15],
                "source": "auth_log"
            }

    # sudo commands
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


real_logs = []

with open(os.path.join(baseDIR, "auth.log")) as f:
    for line in f:
        parsed = parse_auth_log(line)
        if parsed:
            real_logs.append(parsed)

# normalise linux logs
def normalise_linux(log):
    return {
        "user": log["user"],
        "action": log["action"],
        "timestamp": log["time"],
        "source": "linux"
    }

# normalise ldap logs
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

with open(os.path.join(LOG_DIR, 'linux_logs.json')) as f:
    for line in f:
        if line.strip():
            log = json.loads(line)
            normalised_logs.append(normalise_linux(log))

with open(os.path.join(LOG_DIR, 'ldap_logs.json')) as f:
    for line in f:
        if line.strip():
            log = json.loads(line)
            normalised_logs.append(normalise_ldap(log))

# for logs in normalised_logs:
#     print(logs)

normalised_logs.extend(real_logs)

# add privilege context to each log
for log in normalised_logs:
    log["privilege"] = get_privilege(log["action"])

#sort logs by timestamp
normalised_logs.sort(key=lambda x: x["timestamp"])


#calculate risk score for each action
def calculate_risk(action, user, privilege):
    score = 0

    # privilege-based scoring
    if privilege == "elevated":
        score += 40
    elif privilege == "high":
        score += 60

    # action-based scoring
    if action == "sudo":
        score += 50
    if "rm -rf" in action:
        score += 30
    if action == "login_failed":
        score += 10
    if "disable" in action:
        score += 20
    if "chmod" in action or "chown" in action:
        score += 15

    return score

# risk scores for sequences of actions
def sequence_risk(actions):
    score = 0

    if "sudo" in actions and any("rm -rf" in a for a in actions):
        score += 50

    if actions.count("login_failed") >= 2:
        score += 20

    return score


# track user actions
user_sessions = {}

for log in normalised_logs:
    user = log["user"]
    
    if user not in user_sessions:
        user_sessions[user] = []
    
    user_sessions[user].append(log["action"])


# score each user based on their actions and sequences
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

for user, score in final_risk.items():
    print(user, "-> FINAL RISK:", score)


# Save normalized logs
with open(os.path.join(LOG_DIR, "normalized_logs.json"), "w") as f:
    json.dump(normalised_logs, f, indent=4)

# Save final risk
with open(os.path.join(LOG_DIR, "risk_scores.json"), "w") as f:
    json.dump(final_risk, f, indent=4)

print(log["user"], log["action"], log["privilege"])