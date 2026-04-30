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