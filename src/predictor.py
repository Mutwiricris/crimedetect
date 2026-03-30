"""
CrimeDetector — loads and dispatches to three independent ML models:
  url_model  → Phishing / Malicious URL detection
  net_model  → Network Intrusion / Attack detection
  cb_model   → Cyberbullying detection
"""

import os
import joblib
import numpy as np
from src.config import MODELS_DIR


class CrimeDetector:
    # Maps (model_type, predicted_class_idx) → human-readable threat category
    _URL_CLASSES = {0: "Phishing", 1: "Legitimate"}
    _NET_CLASSES = {0: "Normal", 1: "Attack"}
    _CB_CLASSES  = {0: "Safe",    1: "Cyberbullying"}

    def __init__(self, models_dir: str = MODELS_DIR):
        self._models_dir = models_dir
        self._url_model, self._url_scaler = self._load("url_model", "url_scaler")
        self._net_model, self._net_scaler = self._load("net_model", "net_scaler")
        self._cb_model,  self._cb_scaler  = self._load("cb_model",  "cb_scaler")

    # ── Internal helpers ────────────────────────────────────────────────────────

    def _load(self, model_name: str, scaler_name: str):
        model_path  = os.path.join(self._models_dir, f"{model_name}.joblib")
        scaler_path = os.path.join(self._models_dir, f"{scaler_name}.joblib")
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            return joblib.load(model_path), joblib.load(scaler_path)
        return None, None

    @property
    def models_loaded(self) -> dict[str, bool]:
        return {
            "url":     self._url_model is not None,
            "network": self._net_model is not None,
            "cyberbullying": self._cb_model is not None,
        }

    def _predict_with(self, model, scaler, class_map: dict, features: list) -> dict:
        if model is None or scaler is None:
            raise RuntimeError(
                "Model not loaded. Run `python train.py` to train models first."
            )
        X = np.array(features, dtype=float).reshape(1, -1)
        X_scaled = scaler.transform(X)
        idx = int(model.predict(X_scaled)[0])
        probs = model.predict_proba(X_scaled)[0]
        confidence = float(np.max(probs))
        category = class_map.get(idx, "Unknown")
        return {
            "is_threat":        category not in {"Legitimate", "Normal", "Safe"},
            "confidence_score": round(confidence, 4),
            "threat_category":  category,
        }

    # ── Public API ──────────────────────────────────────────────────────────────

    def predict(self, input_type: str, features: list) -> dict:
        """
        Dispatch to the correct model by input_type.
        Returns: {is_threat, confidence_score, threat_category, model_used}
        """
        if input_type == "url":
            result = self._predict_with(self._url_model, self._url_scaler, self._URL_CLASSES, features)
            result["model_used"] = "url_model"
        elif input_type == "network":
            result = self._predict_with(self._net_model, self._net_scaler, self._NET_CLASSES, features)
            result["model_used"] = "net_model"
        elif input_type == "cyberbullying":
            result = self._predict_with(self._cb_model, self._cb_scaler, self._CB_CLASSES, features)
            result["model_used"] = "cb_model"
        else:
            raise ValueError(f"Unknown input_type: {input_type!r}")
        return result
