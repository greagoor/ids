import joblib
from ml.feature_extractor import extract_features

# Load models once
attack_model = joblib.load("attack_model.pkl")
severity_model = joblib.load("severity_model.pkl")

def predict(http):
    features = extract_features(http)
    features_2d = [features]

    proba_attack = attack_model.predict_proba(features_2d)[0]
    attack_pred = attack_model.predict(features_2d)[0]
    # Use the probability of the *predicted* class, not the max across all
    attack_classes = list(attack_model.classes_)
    attack_prob = proba_attack[attack_classes.index(attack_pred)]

    proba_sev = severity_model.predict_proba(features_2d)[0]
    severity_pred = severity_model.predict(features_2d)[0]
    sev_classes = list(severity_model.classes_)
    severity_prob = proba_sev[sev_classes.index(severity_pred)]

    return {
        "attack_type": int(attack_pred),
        "attack_confidence": float(round(attack_prob * 100, 2)),
        "severity": int(severity_pred),
        "severity_confidence": float(round(severity_prob * 100, 2))
    }
