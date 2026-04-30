# risk_engine.py

PRIVILEGE_WEIGHTS = {
    "elevated": 30,
    "high": 50,
    "normal": 0,
}

ACTION_WEIGHTS = {
    "sudo": 40,
    "login_failed": 10,
    "login_success": 0,
}

DESTRUCTIVE_KEYWORDS = ["rm -rf", "dd if=", "mkfs", "shred"]

MAX_POSSIBLE_SCORE = 300  # used for normalization


def get_privilege(action: str) -> str:
    # Use exact token matching — avoids "su" matching "resume", "issue" etc.
    tokens = action.lower().split()
    if "sudo" in tokens or tokens[0:1] == ["su"]:
        return "elevated"
    if any(kw in action for kw in ["rm -rf", "dd if=", "mkfs", "shred"]):
        return "high"
    if any(kw in action for kw in ["chmod", "chown"]):
        return "elevated"
    return "normal"


def calculate_risk(action: str, user: str, privilege: str) -> int:
    score = 0
    score += PRIVILEGE_WEIGHTS.get(privilege, 0)   # privilege contributes once
    score += ACTION_WEIGHTS.get(action, 0)          # named actions contribute once
    if any(kw in action for kw in DESTRUCTIVE_KEYWORDS):
        score += 25
    return score


def sequence_risk(actions: list) -> int:
    """
    Detects dangerous action sequences.
    Returns a raw score — gets added to the user's total before normalization.
    """
    score = 0
    failed_logins = actions.count("login_failed")

    # Pattern: brute-force attempt followed by privilege escalation
    if failed_logins >= 2 and "sudo" in actions:
        failed_idx = max(i for i, a in enumerate(actions) if a == "login_failed")
        sudo_idx = next((i for i, a in enumerate(actions) if a == "sudo"), -1)
        if sudo_idx > failed_idx:
            score += 60   # failed logins THEN sudo — highly suspicious

    if failed_logins >= 2:
        score += 20

    # Pattern: privilege escalation then destruction
    if "sudo" in actions and any(kw in a for a in actions for kw in DESTRUCTIVE_KEYWORDS):
        score += 50

    return score


def normalize_score(raw: int, max_score: int = MAX_POSSIBLE_SCORE) -> float:
    """Returns a 0.0–100.0 risk score. Clamps at 100."""
    return round(min(raw / max_score * 100, 100.0), 1)


def risk_level(normalized: float) -> str:
    """Human-readable label for reporting + dashboard."""
    if normalized >= 75:
        return "CRITICAL"
    elif normalized >= 50:
        return "HIGH"
    elif normalized >= 25:
        return "MEDIUM"
    return "LOW"