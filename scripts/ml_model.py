# ml_model.py

import joblib
import os
from sklearn.ensemble import IsolationForest

MODEL_PATH = "cpam_model.pkl"

# Hand-label your known synthetic scenarios here.
# Even 10–15 users gives you something to evaluate against.
# Set to None for users you genuinely don't know.
GROUND_TRUTH = {
    # "alice": "ANOMALY",
    # "bob": "NORMAL",
}


def extract_features(user_sessions: dict) -> tuple[list, list]:
    X, users = [], []
    for user, actions in user_sessions.items():
        session_duration = len(actions)  # proxy until real timestamps added
        features = [
            actions.count("sudo"),
            sum(1 for a in actions if any(kw in a for kw in ["rm -rf", "dd if=", "shred"])),
            actions.count("login_failed"),
            actions.count("login_success"),
            session_duration,
            # ratio of failed to total logins (avoids penalizing active users unfairly)
            actions.count("login_failed") / max(session_duration, 1),
        ]
        X.append(features)
        users.append(user)
    return X, users


def train_and_save(user_sessions: dict) -> IsolationForest:
    X, _ = extract_features(user_sessions)
    # contamination=0.05 means we expect ~5% of users to be anomalous — realistic
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    print(f"[ML] Model trained on {len(X)} users and saved to {MODEL_PATH}")
    return model


def load_or_train(user_sessions: dict) -> IsolationForest:
    """Load saved model if it exists, otherwise train fresh."""
    if os.path.exists(MODEL_PATH):
        print(f"[ML] Loading saved model from {MODEL_PATH}")
        return joblib.load(MODEL_PATH)
    return train_and_save(user_sessions)


def run_anomaly_detection(user_sessions: dict, retrain: bool = False) -> dict:
    if retrain or not os.path.exists(MODEL_PATH):
        model = train_and_save(user_sessions)
    else:
        model = load_or_train(user_sessions)

    X, users = extract_features(user_sessions)
    predictions = model.predict(X)
    scores = model.decision_function(X)  # negative = more anomalous

    results = {}
    for i, user in enumerate(users):
        results[user] = {
            "ml_flag": "ANOMALY" if predictions[i] == -1 else "NORMAL",
            "anomaly_score": round(float(scores[i]), 4),  # for dashboard display
        }

    evaluate(results)
    return results


def evaluate(results: dict):
    """
    Compares ML predictions against hand-labeled ground truth.
    Only runs if GROUND_TRUTH has entries.
    """
    labeled = {u: v for u, v in GROUND_TRUTH.items() if v is not None}
    if not labeled:
        print("[Eval] No ground truth labels set — skipping evaluation.")
        print("[Eval] Add labels to GROUND_TRUTH in ml_model.py to enable metrics.")
        return

    tp = fp = tn = fn = 0
    for user, true_label in labeled.items():
        pred = results.get(user, {}).get("ml_flag", "NORMAL")
        if true_label == "ANOMALY" and pred == "ANOMALY":
            tp += 1
        elif true_label == "NORMAL" and pred == "ANOMALY":
            fp += 1
        elif true_label == "NORMAL" and pred == "NORMAL":
            tn += 1
        elif true_label == "ANOMALY" and pred == "NORMAL":
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("\n[Eval] === ML Evaluation ===")
    print(f"  Labeled users : {len(labeled)}")
    print(f"  True Positives: {tp}  False Positives: {fp}")
    print(f"  True Negatives: {tn}  False Negatives: {fn}")
    print(f"  Precision : {precision:.2f}")
    print(f"  Recall    : {recall:.2f}")
    print(f"  F1 Score  : {f1:.2f}")
    print("=" * 30)