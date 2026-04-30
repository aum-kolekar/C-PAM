from sklearn.ensemble import IsolationForest

def extract_features(user_sessions):
    X = []
    users = []

    for user, actions in user_sessions.items():
        features = [    actions.count("sudo"),                         # privilege escalation
                        sum(1 for a in actions if "rm -rf" in a),      # destructive
                        actions.count("login_failed"),                 # failed attempts
                        actions.count("login_success"),                # login activity
                        len(actions),                                  # total activity
                    ]

        X.append(features)
        users.append(user)

    return X, users


def run_anomaly_detection(user_sessions):
    X, users = extract_features(user_sessions)

    model = IsolationForest(contamination=0.3)
    model.fit(X)

    predictions = model.predict(X)

    results = {}
    for i, user in enumerate(users):
        results[user] = "ANOMALY" if predictions[i] == -1 else "NORMAL"

    return results