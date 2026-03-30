"""
Feature extraction for three independent crime-detection models.

Each extractor mirrors the exact columns used during training:
  - URL features  (19 features) → url_model
  - Network features (23 features) → net_model
  - Cyberbullying features (4 features) → cb_model
"""

import re
from urllib.parse import urlparse
from typing import Union


# ── URL / Phishing ─────────────────────────────────────────────────────────────
# Matches the column selection used in train.py for the PhiUSIIL dataset.
URL_FEATURE_NAMES = [
    "URLLength", "DomainLength", "TLDLength", "NoOfSubDomain", "HasObfuscation",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS"
]


def extract_url_features(url: str) -> list[float]:
    """Extract 15 URL structural features from a raw URL string.

    Feature counts are computed over the FULL URL string to match the
    PhiUSIIL dataset's exact column computation semantics.
    """
    parsed = urlparse(url)
    domain = parsed.netloc or ""
    full = url

    url_len = len(full)
    domain_len = len(domain)

    # Subdomain count: tokens in domain minus registered domain
    domain_parts = domain.split(".")
    n_subdomains = max(0, len(domain_parts) - 2)

    tld = domain_parts[-1] if domain_parts else ""
    tld_len = len(tld)

    has_https = 1.0 if url.startswith("https://") else 0.0

    # Obfuscation: %XX hex encoding in URL
    has_obfuscation = 1.0 if re.search(r"%[0-9a-fA-F]{2}", full) else 0.0

    # Count letters and digits over FULL URL (matches dataset column NoOfLettersInURL)
    n_letters = len(re.findall(r"[a-zA-Z]", full))
    n_digits  = len(re.findall(r"\d", full))
    letter_ratio = n_letters / url_len if url_len else 0.0
    digit_ratio  = n_digits  / url_len if url_len else 0.0

    # Special chars (dataset: '=', '?', '&' counted separately; others combined)
    n_equals = full.count("=")
    n_qmark  = full.count("?")
    n_amp    = full.count("&")
    # NoOfOtherSpecialCharsInURL: chars outside alphanumeric, '.', '/', ':', '-', '_'
    other_special = len(re.findall(r"[^a-zA-Z0-9./:?=&_\-]", full))
    total_special = n_equals + n_qmark + n_amp + other_special
    special_ratio = total_special / url_len if url_len else 0.0

    return [
        float(url_len),
        float(domain_len),
        float(tld_len),
        float(n_subdomains),
        float(has_obfuscation),
        float(n_letters),
        float(letter_ratio),
        float(n_digits),
        float(digit_ratio),
        float(n_equals),
        float(n_qmark),
        float(n_amp),
        float(other_special),
        float(special_ratio),
        float(has_https),
    ]


# ── Network / Intrusion ─────────────────────────────────────────────────────────
# Matches the 23 numeric columns selected from UNSW_NB15_training-set.csv in train.py.
NET_FEATURE_NAMES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "swin", "dwin",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_ltm", "ct_srv_dst",
]


def extract_network_features(log_data: dict) -> list[float]:
    """Extract 23 numeric network features from a log dict."""
    return [float(log_data.get(col, 0.0)) for col in NET_FEATURE_NAMES]


# ── Cyberbullying ───────────────────────────────────────────────────────────────
# Matches the 4 feature columns from 6. CB_Labels.csv in train.py.
CB_FEATURE_NAMES = [
    "Total_messages", "Aggressive_Count", "Intent_to_Harm", "Peerness",
]

_THREAT_KEYWORDS = [
    "kill", "die", "hate", "attack", "hurt", "beat", "punch", "fight",
    "destroy", "threat", "ugly", "stupid", "idiot", "loser", "worthless",
]


def extract_cyberbullying_features(data: Union[str, dict]) -> list[float]:
    """Extract 4 cyberbullying features.

    Accepts either:
      - A dict with keys: total_messages, aggressive_count, intent_to_harm, peerness
      - A raw text string (features estimated via heuristics)
    """
    if isinstance(data, dict):
        # Normalise key names (Accept both camelCase and snake_case)
        def _get(d, *keys):
            for k in keys:
                if k in d:
                    return float(d[k])
                kl = k.lower().replace("_", "")
                for dk in d:
                    if dk.lower().replace("_", "") == kl:
                        return float(d[dk])
            return 0.0

        total = _get(data, "Total_messages", "total_messages", "totalMessages")
        aggressive = _get(data, "Aggressive_Count", "aggressive_count", "aggressiveCount")
        intent = _get(data, "Intent_to_Harm", "intent_to_harm", "intentToHarm")
        peerness = _get(data, "Peerness", "peerness")
        return [total, aggressive, intent, peerness]

    # Raw text fallback — estimate stats from message content
    text = str(data).lower()
    words = text.split()
    n_words = max(len(words), 1)
    hit = sum(1 for kw in _THREAT_KEYWORDS if kw in text)
    aggressive_ratio = hit / n_words
    intent_to_harm = min(1.0, hit * 0.25)
    peerness = 0.5  # unknown without user-graph context

    return [
        float(n_words),             # Total_messages ≈ word count (proxy)
        float(hit),                 # Aggressive_Count ≈ keyword hits
        float(intent_to_harm),      # Intent_to_Harm
        float(peerness),            # Peerness (unknown → neutral)
    ]


# ── Router ──────────────────────────────────────────────────────────────────────

class FeatureExtractor:
    @staticmethod
    def process_input(input_type: str, raw_data) -> list[float]:
        if input_type == "url":
            return extract_url_features(str(raw_data))
        elif input_type == "network":
            d = raw_data if isinstance(raw_data, dict) else raw_data.dict()
            return extract_network_features(d)
        elif input_type == "cyberbullying":
            if hasattr(raw_data, "model_dump"):
                d = raw_data.model_dump()
            elif hasattr(raw_data, "dict"):
                d = raw_data.dict()
            else:
                d = raw_data
            return extract_cyberbullying_features(d)
        else:
            raise ValueError(f"Unknown input_type: {input_type!r}. Must be 'url', 'network', or 'cyberbullying'.")
