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