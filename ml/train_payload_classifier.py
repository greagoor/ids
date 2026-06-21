# ml/train_payload_classifier.py

import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.feature_extraction.text import TfidfVectorizer
from imblearn.over_sampling import SMOTE
import re

# ── 1. Load SQLi ──────────────────────────────────────────────────────────────
print("Loading SQLi dataset...")
sqli = pd.read_csv("C:\\csPR\\sqli.csv")   # change to your filename
sqli = sqli[["Sentence", "Label"]].copy()

# Label column is messy — keep only rows where Label is exactly 0 or 1
sqli["Label"] = pd.to_numeric(sqli["Label"], errors="coerce")
sqli.dropna(subset=["Label"], inplace=True)
sqli["Label"] = sqli["Label"].astype(int)
sqli = sqli[sqli["Label"].isin([0, 1])]
sqli["attack_type"] = sqli["Label"].apply(lambda x: 1 if x == 1 else 0)
# 1 = SQLi

print(f"SQLi shape after cleaning: {sqli.shape}")
print(f"SQLi labels:\n{sqli['attack_type'].value_counts()}\n")

# ── 2. Load XSS ───────────────────────────────────────────────────────────────
print("Loading XSS dataset...")
xss = pd.read_csv("C:\\csPR\\xss.csv")    # change to your filename
xss = xss[["Sentence", "Label"]].copy()
xss["Label"] = pd.to_numeric(xss["Label"], errors="coerce")
xss.dropna(subset=["Label"], inplace=True)
xss["Label"] = xss["Label"].astype(int)
xss = xss[xss["Label"].isin([0, 1])]
xss["attack_type"] = xss["Label"].apply(lambda x: 2 if x == 1 else 0)
# 2 = XSS

print(f"XSS shape after cleaning: {xss.shape}")
print(f"XSS labels:\n{xss['attack_type'].value_counts()}\n")

# ── 3. Combine ────────────────────────────────────────────────────────────────
print("Combining datasets...")

# From SQLi — take all positives + half the benign
sqli_pos = sqli[sqli["attack_type"] == 1]
sqli_neg = sqli[sqli["attack_type"] == 0].sample(
    min(5000, len(sqli[sqli["attack_type"] == 0])),
    random_state=42
)

# From XSS — take all positives + half the benign
xss_pos  = xss[xss["attack_type"] == 2]
xss_neg  = xss[xss["attack_type"] == 0].sample(
    min(5000, len(xss[xss["attack_type"] == 0])),
    random_state=42
)

# Combine — benign from both sources, attacks labeled separately
df = pd.concat([sqli_pos, sqli_neg, xss_pos, xss_neg], ignore_index=True)
df.dropna(subset=["Sentence"], inplace=True)
df["Sentence"] = df["Sentence"].astype(str).str.strip()
df = df[df["Sentence"].str.len() > 0]

print(f"Combined shape: {df.shape}")
print(f"Label distribution:\n{df['attack_type'].value_counts()}")
print("  0 = Benign, 1 = SQLi, 2 = XSS\n")

# ── 4. Feature extraction — TF-IDF on raw text ────────────────────────────────
print("Extracting TF-IDF features...")
tfidf = TfidfVectorizer(
    analyzer="char_wb",     # character-level — better for attack payloads
    ngram_range=(2, 4),     # 2 to 4 char ngrams
    max_features=3000,
    min_df=2,
    sublinear_tf=True
)

X = tfidf.fit_transform(df["Sentence"])
y = df["attack_type"].values
print(f"Feature matrix: {X.shape}")

# ── 5. Train/test split ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── 6. SMOTE ──────────────────────────────────────────────────────────────────
print("Applying SMOTE...")
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
print(f"After SMOTE: {dict(zip(*np.unique(y_train_bal, return_counts=True)))}")

# ── 7. Train ──────────────────────────────────────────────────────────────────
print("Training payload classifier...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train_bal, y_train_bal)

# ── 8. Calibrate ──────────────────────────────────────────────────────────────
print("Calibrating...")
calibrated = CalibratedClassifierCV(rf, method="isotonic", cv=3)
calibrated.fit(X_train_bal, y_train_bal)

# ── 9. Evaluate ───────────────────────────────────────────────────────────────
print("\n── Evaluation ──")
y_pred = calibrated.predict(X_test)
print(classification_report(
    y_test, y_pred,
    target_names=["Benign", "SQLi", "XSS"]
))

# ── 10. Save ──────────────────────────────────────────────────────────────────
os.makedirs("models", exist_ok=True)

with open("models/payload_classifier.pkl", "wb") as f:
    pickle.dump(calibrated, f)

with open("models/payload_tfidf.pkl", "wb") as f:
    pickle.dump(tfidf, f)

with open("models/payload_rf_base.pkl", "wb") as f:
    pickle.dump(rf, f)

print("\nDone. Models saved:")
print("  models/payload_classifier.pkl  ← use at runtime")
print("  models/payload_tfidf.pkl       ← TF-IDF vectorizer")
print("  models/payload_rf_base.pkl     ← base RF for SHAP")

# ── 11. Sanity check ──────────────────────────────────────────────────────────
LABELS = {0: "Benign", 1: "SQLi", 2: "XSS"}

print("\n── Sanity Check ──")
test_payloads = [
    "' OR 1=1 --",
    "SELECT * FROM users WHERE id=1",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "hello world this is normal text",
    "python tutorial for beginners",
]

for payload in test_payloads:
    vec   = tfidf.transform([payload])
    proba = calibrated.predict_proba(vec)[0]
    pred  = calibrated.predict(vec)[0]
    print(f"Payload:    {payload[:50]}")
    print(f"Prediction: {LABELS[pred]} "
          f"(benign:{proba[0]:.2f} sqli:{proba[1]:.2f} xss:{proba[2]:.2f})")
    print()