"""
AI Crime Detection Engine — Training Script
Trains three separate Random Forest classifiers on real datasets:
  1. URL / Phishing   ← PhiUSIIL_Phishing_URL_Dataset.csv
  2. Network Attack   ← UNSW_NB15_training-set.csv
  3. Cyberbullying    ← 6. CB_Labels.csv
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

# Allow running from project root without installing as a package
sys.path.insert(0, os.path.dirname(__file__))
from src.config import MODELS_DIR, URL_DATASET, NET_DATASET, CB_DATASET

os.makedirs(MODELS_DIR, exist_ok=True)


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _save(obj, name: str):
    path = os.path.join(MODELS_DIR, f"{name}.joblib")
    joblib.dump(obj, path)
    print(f"  Saved → {path}")


def _train(X: np.ndarray, y: np.ndarray, label: str):
    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        n_jobs=2,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_s, y)
    preds = clf.predict(X_s)
    print(f"\n── {label} — Training report ──")
    print(classification_report(y, preds, zero_division=0))
    return clf, scaler


# ── 1. URL / Phishing model ──────────────────────────────────────────────────────

def train_url_model(sample: int = 200_000):
    print(f"\n[1/3] URL / Phishing model  ({URL_DATASET})")
    df = pd.read_csv(URL_DATASET, low_memory=False)
    print(f"  Loaded {len(df):,} rows")

    feature_cols = [
        "URLLength", "DomainLength", "TLDLength", "NoOfSubDomain", "HasObfuscation",
        "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
        "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS"
    ]
    label_col = "label"

    available = [c for c in feature_cols if c in df.columns]
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        print(f"  ⚠ Missing columns (will pad with 0): {missing}")

    df = df.dropna(subset=[label_col])
    if len(df) > sample:
        df = df.sample(sample, random_state=42)
        print(f"  Sampled to {len(df):,} rows")

    X = np.zeros((len(df), len(feature_cols)))
    for i, col in enumerate(feature_cols):
        if col in df.columns:
            X[:, i] = pd.to_numeric(df[col], errors="coerce").fillna(0).values

    y = pd.to_numeric(df[label_col], errors="coerce").fillna(0).values.astype(int)
    clf, scaler = _train(X, y, "URL/Phishing")
    _save(clf, "url_model")
    _save(scaler, "url_scaler")


# ── 2. Network Intrusion model ───────────────────────────────────────────────────

def train_network_model():
    print(f"\n[2/3] Network Intrusion model  ({NET_DATASET})")
    df = pd.read_csv(NET_DATASET, low_memory=False)
    print(f"  Loaded {len(df):,} rows")

    feature_cols = [
        "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
        "sttl", "dttl", "sload", "dload", "sloss", "dloss",
        "sinpkt", "dinpkt", "sjit", "djit", "swin", "dwin",
        "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_ltm", "ct_srv_dst",
    ]
    label_col = "label"

    df = df.dropna(subset=[label_col])
    X = np.zeros((len(df), len(feature_cols)))
    for i, col in enumerate(feature_cols):
        if col in df.columns:
            X[:, i] = pd.to_numeric(df[col], errors="coerce").fillna(0).values
        else:
            print(f"  ⚠ Missing column: {col}")

    y = pd.to_numeric(df[label_col], errors="coerce").fillna(0).values.astype(int)
    clf, scaler = _train(X, y, "Network/Intrusion")
    _save(clf, "net_model")
    _save(scaler, "net_scaler")


# ── 3. Cyberbullying model ───────────────────────────────────────────────────────

def train_cb_model():
    print(f"\n[3/3] Cyberbullying model  ({CB_DATASET})")
    df = pd.read_csv(CB_DATASET, low_memory=False)
    print(f"  Loaded {len(df):,} rows")

    feature_cols = [
        "Total_messages", "Aggressive_Count", "Intent_to_Harm", "Peerness",
    ]
    label_col = "CB_Label"

    df = df.dropna(subset=[label_col])
    X = np.zeros((len(df), len(feature_cols)))
    for i, col in enumerate(feature_cols):
        if col in df.columns:
            X[:, i] = pd.to_numeric(df[col], errors="coerce").fillna(0).values
        else:
            print(f"  ⚠ Missing column: {col}")

    y = pd.to_numeric(df[label_col], errors="coerce").fillna(0).values.astype(int)
    clf, scaler = _train(X, y, "Cyberbullying")
    _save(clf, "cb_model")
    _save(scaler, "cb_scaler")


# ── Entry point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AI Crime Detection Engine — Training Pipeline")
    print("=" * 60)
    train_url_model()
    train_network_model()
    train_cb_model()
    print("\n✓ All models trained and saved to models/")
    print("  Start the server: uvicorn main:app --port 8000")
