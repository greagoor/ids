import joblib
from ml.feature_extractor import extract_features

# Load models once
attack_model = joblib.load("attack_model.pkl")
severity_model = joblib.load("severity_model.pkl")

def predict(http):
    features = extract_features(http)
    features_2d = [features]

    attack_pred = attack_model.predict(features_2d)[0]
    attack_prob = max(attack_model.predict_proba(features_2d)[0])

    severity_pred = severity_model.predict(features_2d)[0]
    severity_prob = max(severity_model.predict_proba(features_2d)[0])

    return {
        "attack_type": int(attack_pred),
        "attack_confidence": float(round(attack_prob * 100, 2)),
        "severity": int(severity_pred),
        "severity_confidence": float(round(severity_prob * 100, 2))
    }
