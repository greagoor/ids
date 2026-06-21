import pandas as pd
import numpy as np
import pickle
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, roc_auc_score,
                             confusion_matrix, ConfusionMatrixDisplay)
from sklearn.feature_selection import VarianceThreshold
from imblearn.over_sampling import SMOTE
import os

# ── 1. Load ───────────────────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv("C:\\csPR\\maliciousUrl.csv")
print(f"Shape: {df.shape}")
print(f"Label distribution:\n{df['type'].value_counts()}\n")

# ── 2. Clean ──────────────────────────────────────────────────────────────────
drop_cols = [
    "url", "type", "domain", "Date_inspection",
    "web_is_live", "web_security_score", "web_forms_count",
    "web_password_fields", "web_has_login", "web_ssl_valid",
    "//", "abnormal_url"
]
df.drop(columns=[c for c in drop_cols if c in df.columns], inplace=True)

df.columns = [c.strip() for c in df.columns]

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
print(f"Shape after cleaning: {df.shape}")

# ── 2b. Keep only features we can compute identically at runtime ──────────────
safe_features = [
    "url_len",
    "?", "-", "=", ".", "%", "+", ",",
    "digits",
    "having_ip_address",       # IP in domain = always suspicious
    "Shortining_Service",      # URL shortener = always suspicious  
    "phish_hyphen_count",      # hyphens in domain = suspicious
    "phish_digit_count",       # digits in domain = suspicious
    "phish_param_count",       # many params = suspicious
    "phish_encoded_chars",     # encoded chars = suspicious
    "defac_path_depth",        # deep paths
    "defac_has_index_php",     # index.php = suspicious
    "defac_has_suspicious_ext", # .php .asp etc
    "label"
]
df = df[[c for c in safe_features if c in df.columns]]
print(f"Using {len(df.columns)-1} safe features for training")

# ── 3. Labels ─────────────────────────────────────────────────────────────────
y = (df["label"] != 0).astype(int)
X = df.drop(columns=["label"])

print(f"Benign: {(y==0).sum()}, Suspicious: {(y==1).sum()}")

# ── 4. Remove near-zero variance features ─────────────────────────────────────
print("Removing low-variance features...")
selector = VarianceThreshold(threshold=0.01)
X_filtered = selector.fit_transform(X)
kept_cols = X.columns[selector.get_support()].tolist()
X = pd.DataFrame(X_filtered, columns=kept_cols)
print(f"Features kept: {len(kept_cols)} / {len(df.columns)-1}")

# ── 5. Save feature column order (CRITICAL for runtime) ───────────────────────
os.makedirs("models", exist_ok=True)
with open("models/feature_columns.pkl", "wb") as f:
    pickle.dump(kept_cols, f)
print(f"Feature columns saved: {kept_cols}")

# ── 6. Train/test split ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── 7. SMOTE — fix class imbalance ────────────────────────────────────────────
print("Applying SMOTE...")
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
print(f"After SMOTE — Benign: {(y_train_bal==0).sum()}, "
      f"Suspicious: {(y_train_bal==1).sum()}")

# ── 8. Train base Random Forest ───────────────────────────────────────────────
print("Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train_bal, y_train_bal)

# ── 9. Calibrate ──────────────────────────────────────────────────────────────
print("Calibrating probabilities...")
calibrated = CalibratedClassifierCV(rf, method="isotonic", cv=3)
calibrated.fit(X_train_bal, y_train_bal)

# ── 10. Evaluate ──────────────────────────────────────────────────────────────
print("\n── Evaluation ──")
y_pred  = calibrated.predict(X_test)
y_proba = calibrated.predict_proba(X_test)[:, 1]

print(classification_report(y_test, y_pred,
      target_names=["Benign", "Suspicious"]))
print(f"ROC-AUC Score: {roc_auc_score(y_test, y_proba):.4f}")

cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(cm, display_labels=["Benign", "Suspicious"])
disp.plot()
plt.title("Suspicion Model — Confusion Matrix")
plt.savefig("models/confusion_matrix.png")
plt.close()
print("Confusion matrix saved to models/confusion_matrix.png")

# ── 11. SHAP ──────────────────────────────────────────────────────────────────
# SHAP explanations happen at runtime per-URL in suspicion_scorer.py
# Built from rf_base.pkl on demand — no need to compute during training
print("Skipping SHAP training plot — explanations handled at runtime.")

# ── 12. Save models ───────────────────────────────────────────────────────────
print("\nSaving models...")

with open("models/suspicion_model.pkl", "wb") as f:
    pickle.dump(calibrated, f)

with open("models/rf_base.pkl", "wb") as f:
    pickle.dump(rf, f)

print("Done. Models saved:")
print("  models/suspicion_model.pkl   ← use this at runtime")
print("  models/rf_base.pkl           ← used by SHAP explainer at runtime")
print("  models/feature_columns.pkl   ← feature order for runtime")

# ── 13. Quick sanity check ────────────────────────────────────────────────────
print("\n── Sanity Check ──")
with open("models/suspicion_model.pkl", "rb") as f:
    loaded = pickle.load(f)

sample_row = X_test.iloc[0:1]
score  = loaded.predict_proba(sample_row)[0][1]
actual = y_test.iloc[0]
print(f"Sample URL score:  {score:.4f}")
print(f"Actual label:      {'Suspicious' if actual == 1 else 'Benign'}")
print(f"Model verdict:     {'Suspicious' if score > 0.5 else 'Benign'}")