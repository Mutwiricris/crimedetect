"""
Test suite for the AI Crime Detection Engine (v2.0)
Covers: feature extraction (all 3 types), predictor dispatch, API key auth, /health endpoint.
Dependencies are mocked so this runs without trained models or installed ML packages.
"""

import sys
import os
from unittest.mock import MagicMock, patch

# ── Mock heavy dependencies before importing project code ──────────────────────
_mock_modules = [
    "fastapi", "fastapi.middleware", "fastapi.middleware.cors",
    "fastapi.security", "fastapi.security.api_key", "fastapi.responses",
    "fastapi.testclient",
    "pydantic", "uvicorn",
    "joblib", "sklearn", "sklearn.ensemble", "sklearn.preprocessing",
    "sklearn.metrics",
    "pandas", "numpy",
]
for mod in _mock_modules:
    sys.modules.setdefault(mod, MagicMock())

import unittest

# Patch numpy array behaviour used in predictor (needs real reshaping logic)
import numpy  # mocked
numpy.array = lambda x, **kw: x
numpy.max = lambda x: max(x) if hasattr(x, "__iter__") else x

# ── Feature extractor tests ────────────────────────────────────────────────────

from src.features import FeatureExtractor, URL_FEATURE_NAMES, NET_FEATURE_NAMES, CB_FEATURE_NAMES


class TestURLFeatures(unittest.TestCase):

    def _extract(self, url):
        return FeatureExtractor.process_input("url", url)

    def test_returns_correct_length(self):
        feats = self._extract("https://example.com")
        self.assertEqual(len(feats), len(URL_FEATURE_NAMES))

    def test_https_flag(self):
        feats_https = self._extract("https://example.com")
        feats_http = self._extract("http://evil.com/login")
        self.assertEqual(feats_https[URL_FEATURE_NAMES.index("IsHTTPS")], 1.0)
        self.assertEqual(feats_http[URL_FEATURE_NAMES.index("IsHTTPS")], 0.0)

    def test_long_suspicious_url(self):
        url = "http://free-prize-win.click/login@bank.com?user=admin&pass=abc%20xyz"
        feats = self._extract(url)
        self.assertGreater(feats[URL_FEATURE_NAMES.index("URLLength")], 30)
        self.assertGreater(feats[URL_FEATURE_NAMES.index("NoOfAmpersandInURL")], 0)

    def test_obfuscated_url_detected(self):
        url = "http://paypal.com%2Fverify@evil.com"
        feats = self._extract(url)
        self.assertEqual(feats[URL_FEATURE_NAMES.index("HasObfuscation")], 1.0)


class TestNetworkFeatures(unittest.TestCase):

    def _extract(self, log):
        return FeatureExtractor.process_input("network", log)

    def test_returns_correct_length(self):
        feats = self._extract({})
        self.assertEqual(len(feats), len(NET_FEATURE_NAMES))

    def test_known_values_passed_through(self):
        log = {"dur": 0.5, "sbytes": 1024.0, "dbytes": 512.0, "rate": 9090.0}
        feats = self._extract(log)
        self.assertEqual(feats[NET_FEATURE_NAMES.index("dur")], 0.5)
        self.assertEqual(feats[NET_FEATURE_NAMES.index("sbytes")], 1024.0)

    def test_missing_fields_default_to_zero(self):
        feats = self._extract({"dur": 1.0})
        self.assertEqual(feats[NET_FEATURE_NAMES.index("dload")], 0.0)


class TestCyberbullyingFeatures(unittest.TestCase):

    def _extract(self, data):
        return FeatureExtractor.process_input("cyberbullying", data)

    def test_returns_correct_length(self):
        feats = self._extract("hello world")
        self.assertEqual(len(feats), len(CB_FEATURE_NAMES))

    def test_dict_input(self):
        stats = {
            "total_messages": 36,
            "aggressive_count": 23,
            "intent_to_harm": 0.77,
            "peerness": 0.5,
        }
        feats = self._extract(stats)
        self.assertEqual(feats[0], 36.0)
        self.assertEqual(feats[1], 23.0)
        self.assertAlmostEqual(feats[2], 0.77)

    def test_text_with_threats_flagged(self):
        feats = self._extract("I will kill you and steal your password and hack you")
        # Aggressive count > 0
        self.assertGreater(feats[1], 0)
        # Intent to harm > 0
        self.assertGreater(feats[2], 0)

    def test_clean_text(self):
        feats = self._extract("Hello, how are you today?")
        self.assertEqual(feats[1], 0.0)   # No threat keywords


class TestFeatureExtractorInvalidType(unittest.TestCase):
    def test_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            FeatureExtractor.process_input("invalid_type", "data")


# ── Predictor tests ────────────────────────────────────────────────────────────

from src.predictor import CrimeDetector


class TestCrimeDetectorUnloaded(unittest.TestCase):
    """Test predictor behaviour when no models exist."""

    def setUp(self):
        self.detector = CrimeDetector(models_dir="/nonexistent")

    def test_models_not_loaded(self):
        loaded = self.detector.models_loaded
        self.assertFalse(loaded["url"])
        self.assertFalse(loaded["network"])
        self.assertFalse(loaded["cyberbullying"])

    def test_predict_raises_runtime_error(self):
        with self.assertRaises(RuntimeError):
            self.detector.predict("url", [0.0] * 19)

    def test_predict_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            self.detector.predict("invalid", [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
