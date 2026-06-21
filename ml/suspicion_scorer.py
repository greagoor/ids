# ml/suspicion_scorer.py

import pickle
import re
import math
import numpy as np
import pandas as pd
import shap
from urllib.parse import urlparse, parse_qs, unquote

# ── Load models once at startup ───────────────────────────────────────────────
with open("models/suspicion_model.pkl", "rb") as f:
    MODEL = pickle.load(f)

with open("models/rf_base.pkl", "rb") as f:
    rf_base = pickle.load(f)

with open("models/feature_columns.pkl", "rb") as f:
    FEATURE_COLUMNS = pickle.load(f)

# Build SHAP explainer from base RF
try:
    EXPLAINER = shap.TreeExplainer(
        rf_base,
        feature_perturbation="tree_path_dependent"
    )
except Exception as e:
    print(f"SHAP explainer init failed (non-critical): {e}")
    EXPLAINER = None

print(f"Model loaded. Expecting {len(FEATURE_COLUMNS)} features.")
print(f"Features: {FEATURE_COLUMNS}")

# ── Constants ─────────────────────────────────────────────────────────────────
SHORTENERS = ["bit.ly", "goo.gl", "tinyurl", "ow.ly", "t.co",
              "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"]
SUSP_EXTS  = {".php", ".asp", ".aspx", ".cgi", ".exe", ".bat", ".sh"}

# ── Feature extraction ────────────────────────────────────────────────────────
def extract_features(url: str) -> dict:
    raw    = url.strip()
    parsed = urlparse(raw if raw.startswith("http") else "http://" + raw)

    domain = parsed.netloc.lower()
    path   = parsed.path.lower()

    clean  = re.sub(r"^https?://", "", raw.lower())

    params = parse_qs(parsed.query)

    SHORTENERS = ["bit.ly","goo.gl","tinyurl","ow.ly","t.co",
                  "is.gd","buff.ly","rebrand.ly","cutt.ly"]
    SUSP_EXTS  = {".php",".asp",".aspx",".cgi",".exe",".bat",".sh"}

    return {
        "url_len":              len(clean),
        "?":                    clean.count("?"),
        "-":                    clean.count("-"),
        "=":                    clean.count("="),
        ".":                    clean.count("."),
        "%":                    clean.count("%"),
        "+":                    clean.count("+"),
        ",":                    clean.count(","),
        "digits":               sum(c.isdigit() for c in clean),
        "having_ip_address":    1 if re.search(
                                    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                                    domain) else 0,
        "Shortining_Service":   1 if any(s in domain for s in SHORTENERS) else 0,
        "phish_hyphen_count":   domain.count("-"),
        "phish_digit_count":    sum(c.isdigit() for c in domain),
        "phish_param_count":    len(params),
        "phish_encoded_chars":  len(re.findall(r"%[0-9a-fA-F]{2}", raw)),
        "defac_path_depth":     path.count("/"),
        "defac_has_index_php":  1 if "index.php" in path else 0,
        "defac_has_suspicious_ext": 1 if any(
                                    path.endswith(e) for e in SUSP_EXTS) else 0,
    }

# ── Align to model feature order ──────────────────────────────────────────────
def _align_features(features: dict) -> pd.DataFrame:
    return pd.DataFrame(
        [[features.get(col, 0) for col in FEATURE_COLUMNS]],
        columns=FEATURE_COLUMNS
    )

# ── SHAP top features ─────────────────────────────────────────────────────────
def _get_top_shap_features(feature_df: pd.DataFrame, n=3) -> list:
    if EXPLAINER is None:
        # Fallback — return top features by raw value
        row = feature_df.iloc[0]
        top = row.abs().nlargest(n)
        return [
            {"feature": col, "value": round(float(row[col]), 4), "impact": 0.0}
            for col in top.index
        ]
    try:
        # Pass numpy array to avoid feature name warnings
        shap_vals = EXPLAINER.shap_values(feature_df.values)

        if isinstance(shap_vals, list):
            # Old SHAP format — list of arrays per class
            vals = shap_vals[1][0]
        else:
            sv = np.array(shap_vals)
            if sv.ndim == 3:
                # Shape: (samples, features, classes)
                vals = sv[0, :, 1]
            else:
                vals = sv[0]

        top_indices = np.argsort(np.abs(vals))[::-1][:n]
        return [
            {
                "feature": FEATURE_COLUMNS[i],
                "value":   round(float(feature_df.iloc[0, i]), 4),
                "impact":  round(float(vals[i]), 4)
            }
            for i in top_indices
        ]
    except Exception:
        # Fallback — return top features by raw value
        row = feature_df.iloc[0]
        top = row.abs().nlargest(n)
        return [
            {"feature": col, "value": round(float(row[col]), 4), "impact": 0.0}
            for col in top.index
        ]

# ── Main scoring function ─────────────────────────────────────────────────────
def score_url(url: str) -> dict:
    """
    Score a URL for suspicion.

    Returns:
    {
        "suspicion_score": 0.84,
        "verdict":         "HIGH",
        "confidence_pct":  84.0,
        "top_features": [
            {"feature": "phish_encoded_chars", "value": 3, "impact": 0.21},
            ...
        ]
    }
    Verdicts: HIGH (>=0.75) / SUSPICIOUS (>=0.50) / LOW (>=0.25) / BENIGN (<0.25)
    """
    try:
        features   = extract_features(url)
        feature_df = _align_features(features)
        score      = float(MODEL.predict_proba(feature_df)[0][1])
        top_feats  = _get_top_shap_features(feature_df)

        if score >= 0.75:
            verdict = "HIGH"
        elif score >= 0.50:
            verdict = "SUSPICIOUS"
        elif score >= 0.25:
            verdict = "LOW"
        else:
            verdict = "BENIGN"

        return {
            "suspicion_score": round(score, 4),
            "verdict":         verdict,
            "confidence_pct":  round(score * 100, 1),
            "top_features":    top_feats
        }

    except Exception as e:
        return {
            "suspicion_score": 0.0,
            "verdict":         "ERROR",
            "confidence_pct":  0.0,
            "top_features":    [],
            "error":           str(e)
        }


# ── Quick test when run directly ──────────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        # Should be HIGH
        "http://paypal-secure-login.xyz/verify?user=admin&token=123%2F456",
        "http://192.168.1.1/admin/config.php?option=com_admin",
        "http://apple-id-suspended.top/signin/confirm/account/update",
        "http://bit.ly/3xK9mP2",
        "http://microsoft-account-verify.tk/login/confirm?session=abc123",

        # Should be BENIGN
        "https://www.google.com/search?q=python+tutorial",
        "https://github.com/user/repo/blob/main/README.md",
        "https://stackoverflow.com/questions/12345/how-to-use-python",
        "https://docs.python.org/3/library/os.html",
        "https://www.wikipedia.org/wiki/Machine_learning",
    ]

    print("\n── Suspicion Scorer Test ──\n")
    for url in test_urls:
        result = score_url(url)
        print(f"URL:      {url[:65]}")
        print(f"Score:    {result['suspicion_score']} "
              f"({result['confidence_pct']}%) → {result['verdict']}")
        print(f"Reasons:  {[f['feature'] for f in result['top_features']]}")
        print()