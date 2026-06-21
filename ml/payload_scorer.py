# ml/payload_scorer.py

import pickle
from typing import Optional

# ── Load models once at startup ───────────────────────────────────────────────
with open("models/payload_classifier.pkl", "rb") as f:
    PAYLOAD_MODEL = pickle.load(f)

with open("models/payload_tfidf.pkl", "rb") as f:
    TFIDF = pickle.load(f)

LABELS = {0: "Benign", 1: "SQLi", 2: "XSS"}

print("Payload classifier loaded.")

# ── Main classify function ────────────────────────────────────────────────────
def classify_payload(payload: str) -> dict:
    """
    Classify a payload as Benign / SQLi / XSS.

    Returns:
    {
        "attack_type":    "SQLi",
        "confidence":     0.99,
        "confidence_pct": 99.0,
        "all_scores": {
            "Benign": 0.00,
            "SQLi":   0.99,
            "XSS":    0.01
        }
    }
    """
    try:
        vec   = TFIDF.transform([payload])
        proba = PAYLOAD_MODEL.predict_proba(vec)[0]
        pred  = int(PAYLOAD_MODEL.predict(vec)[0])

        return {
            "attack_type":    LABELS[pred],
            "confidence":     round(float(proba[pred]), 4),
            "confidence_pct": round(float(proba[pred]) * 100, 1),
            "all_scores": {
                "Benign": round(float(proba[0]), 4),
                "SQLi":   round(float(proba[1]), 4),
                "XSS":    round(float(proba[2]), 4),
            }
        }

    except Exception as e:
        return {
            "attack_type":    "Unknown",
            "confidence":     0.0,
            "confidence_pct": 0.0,
            "all_scores":     {"Benign": 0, "SQLi": 0, "XSS": 0},
            "error":          str(e)
        }


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_payloads = [
        "' OR 1=1 --",
        "1; DROP TABLE users--",
        "UNION SELECT username, password FROM users--",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "/etc/passwd",
        "hello world",
        "search?q=python tutorial",
    ]

    print("\n── Payload Classifier Test ──\n")
    for payload in test_payloads:
        result = classify_payload(payload)
        print(f"Payload:  {payload[:55]}")
        print(f"Result:   {result['attack_type']} "
              f"({result['confidence_pct']}%)")
        print(f"Scores:   {result['all_scores']}")
        print()