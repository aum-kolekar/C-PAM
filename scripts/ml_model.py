# ml_model.py

import joblib
import os
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH        = "cpam_model.pkl"
ACTION_MODEL_PATH = "cpam_action_model.pkl"

GROUND_TRUTH = {
    # "admin1": "ANOMALY",
    # "admin2": "NORMAL",
}

DESTRUCTIVE = ["rm -rf", "dd if=", "mkfs", "shred"]
RECON       = ["whoami", "id", "cat /etc/passwd", "cat /etc/shadow",
               "netstat", "ps aux", "ls /home", "find /"]
EXFIL       = ["scp ", "rsync ", "curl ", "wget ", "nc "]


# ── User-level model (existing — unchanged) ───────────────────────────────────

def extract_features(user_sessions: dict) -> tuple:
    X, users = [], []
    for user, actions in user_sessions.items():
        session_duration = len(actions)
        features = [
            actions.count("sudo"),
            sum(1 for a in actions if any(kw in a for kw in DESTRUCTIVE)),
            actions.count("login_failed"),
            actions.count("login_success"),
            session_duration,
            actions.count("login_failed") / max(session_duration, 1),
        ]
        X.append(features)
        users.append(user)
    return X, users


def train_and_save(user_sessions: dict) -> IsolationForest:
    X, _ = extract_features(user_sessions)
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    print(f"[ML] User model trained on {len(X)} users → {MODEL_PATH}")
    return model


def load_or_train(user_sessions: dict) -> IsolationForest:
    if os.path.exists(MODEL_PATH):
        print(f"[ML] Loading saved user model from {MODEL_PATH}")
        return joblib.load(MODEL_PATH)
    return train_and_save(user_sessions)


def run_anomaly_detection(user_sessions: dict, retrain: bool = False) -> dict:
    if retrain or not os.path.exists(MODEL_PATH):
        model = train_and_save(user_sessions)
    else:
        model = load_or_train(user_sessions)

    X, users     = extract_features(user_sessions)
    predictions  = model.predict(X)
    scores       = model.decision_function(X)

    results = {}
    for i, user in enumerate(users):
        results[user] = {
            "ml_flag"      : "ANOMALY" if predictions[i] == -1 else "NORMAL",
            "anomaly_score": round(float(scores[i]), 4),
        }

    evaluate(results)
    return results


# ── Action-level model (new) ──────────────────────────────────────────────────

def extract_action_features(action: str, context: list) -> list:
    is_sudo        = 1 if action == "sudo" or action.startswith("sudo ") else 0
    is_destructive = 1 if any(kw in action for kw in DESTRUCTIVE) else 0
    is_recon       = 1 if any(kw in action for kw in RECON) else 0
    is_failed      = 1 if action == "login_failed" else 0
    is_exfil       = 1 if any(kw in action for kw in EXFIL) else 0

    ctx_fails      = context.count("login_failed")
    ctx_sudo       = context.count("sudo")
    ctx_destructive= sum(1 for a in context if any(kw in a for kw in DESTRUCTIVE))
    position       = min(len(context) / 50.0, 1.0)
    fail_ratio     = ctx_fails / max(len(context), 1)
    recent         = context[-3:] if len(context) >= 3 else context
    recent_fail    = 1 if "login_failed" in recent else 0

    # Extra weight — destructive after sudo is the most critical pattern
    destructive_after_sudo = 1 if (is_destructive and ctx_sudo > 0) else 0
    failed_then_sudo = 1 if (is_sudo and ctx_fails >= 2) else 0

    return [
        is_sudo, is_destructive, is_recon, is_failed, is_exfil,
        ctx_fails, ctx_sudo, ctx_destructive,
        position, fail_ratio, recent_fail,
        destructive_after_sudo,   # new
        failed_then_sudo,         # new
    ]


def build_action_training_data(user_sessions: dict) -> list:
    """
    Builds a training set where each row is one action
    with its session context at that point in time.
    """
    X = []
    for user, actions in user_sessions.items():
        for i, action in enumerate(actions):
            context = actions[:i]   # everything before this action
            X.append(extract_action_features(action, context))
    return X


def train_action_model(user_sessions: dict) -> IsolationForest:
    X = build_action_training_data(user_sessions)
    if len(X) < 5:
        print("[ML] Not enough actions to train action model")
        return None
    model = IsolationForest(contamination=0.1, random_state=42)  # raised from 0.05
    model.fit(X)
    joblib.dump(model, ACTION_MODEL_PATH)
    print(f"[ML] Action model trained on {len(X)} samples → {ACTION_MODEL_PATH}")
    return model

def load_action_model() -> IsolationForest:
    if os.path.exists(ACTION_MODEL_PATH):
        return joblib.load(ACTION_MODEL_PATH)
    return None


def score_action(action: str, context: list) -> dict:
    """
    Scores a single action against the action-level model.
    This is called by monitor.py for every new log line.

    Returns:
        {
          "action"       : str,
          "ml_flag"      : "ANOMALY" or "NORMAL",
          "anomaly_score": float,   # negative = more anomalous
          "confidence"   : str,     # HIGH / MEDIUM / LOW
        }
    """
    model = load_action_model()
    if model is None:
        return {
            "action"       : action,
            "ml_flag"      : "UNKNOWN",
            "anomaly_score": 0.0,
            "confidence"   : "LOW",
        }

    features    = extract_action_features(action, context)
    prediction  = model.predict([features])[0]
    anom_score  = round(float(model.decision_function([features])[0]), 4)

    # Confidence based on how far from the decision boundary
    abs_score = abs(anom_score)
    if abs_score > 0.15:
        confidence = "HIGH"
    elif abs_score > 0.07:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "action"       : action,
        "ml_flag"      : "ANOMALY" if prediction == -1 else "NORMAL",
        "anomaly_score": anom_score,
        "confidence"   : confidence,
    }


# ── Evaluation (unchanged) ────────────────────────────────────────────────────

def evaluate(results: dict):
    labeled = {u: v for u, v in GROUND_TRUTH.items() if v is not None}
    if not labeled:
        print("[Eval] No ground truth labels — skipping evaluation.")
        return

    tp = fp = tn = fn = 0
    for user, true_label in labeled.items():
        pred = results.get(user, {}).get("ml_flag", "NORMAL")
        if true_label == "ANOMALY" and pred == "ANOMALY": tp += 1
        elif true_label == "NORMAL"  and pred == "ANOMALY": fp += 1
        elif true_label == "NORMAL"  and pred == "NORMAL":  tn += 1
        elif true_label == "ANOMALY" and pred == "NORMAL":  fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)

    print(f"\n[Eval] Precision: {precision:.2f}  "
          f"Recall: {recall:.2f}  F1: {f1:.2f}")