def get_privilege(action):
    if "sudo" in action or "su" in action:
        return "elevated"
    elif "rm -rf" in action or "dd" in action:
        return "high"
    elif "chmod" in action or "chown" in action:
        return "elevated"
    else:
        return "normal"


def calculate_risk(action, user, privilege):
    score = 0

    if privilege == "elevated":
        score += 40
    elif privilege == "high":
        score += 60

    if action == "sudo":
        score += 50
    if "rm -rf" in action:
        score += 30
    if action == "login_failed":
        score += 10

    return score


def sequence_risk(actions):
    score = 0

    if "sudo" in actions and any("rm -rf" in a for a in actions):
        score += 50

    if actions.count("login_failed") >= 2:
        score += 20

    return score