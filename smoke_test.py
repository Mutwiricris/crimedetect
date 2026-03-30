#!/usr/bin/env python3
"""
Quick direct inference test — bypasses FastAPI, loads models directly.
Tests all 3 models with real-world examples.
"""
import sys, joblib, numpy as np
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

from src.features import extract_url_features, extract_network_features, extract_cyberbullying_features
from src.predictor import CrimeDetector

print("=" * 58)
print("  AI Crime Engine — Direct Inference Smoke Test")
print("=" * 58)

try:
    det = CrimeDetector()
    loaded = det.models_loaded
    print(f"\n  Models loaded: {loaded}")
    missing = [k for k,v in loaded.items() if not v]
    if missing:
        print(f"\n  ❌ Missing models: {missing}")
        print("  Run: venv/bin/python train.py")
        sys.exit(1)
except Exception as e:
    print(f"\n  ❌ Failed to load models: {e}")
    sys.exit(1)

ok = True

# ── 1. URL / Phishing ─────────────────────────────────────────────
print("\n[ URL / Phishing ]")
tests_url = [
    ("https://www.google.com",                                False),
    ("https://www.southbankmosaics.com",                      False),
    ("http://paypal-verify-urgent.tk/login?user=admin&x=1",  True),
    ("http://free-prize-winner.click/claim?id=99&ref=spam",  True),
]
for url, expect_threat in tests_url:
    feats = extract_url_features(url)
    r = det.predict("url", feats)
    flag = "✓" if r["is_threat"] == expect_threat else "✗"
    if r["is_threat"] != expect_threat:
        ok = False
    print(f"  {flag} [{r['threat_category']:12}] conf={r['confidence_score']:.3f}  {url[:55]}")

# ── 2. Network / Intrusion ────────────────────────────────────────
print("\n[ Network / Intrusion ]")
normal_flow = dict(dur=0.12, spkts=6, dpkts=4, sbytes=512, dbytes=256, rate=50.0,
                   sttl=64, dttl=64, sload=400.0, dload=200.0, sloss=0, dloss=0,
                   sinpkt=0.02, dinpkt=0.03, sjit=0.0, djit=0.0, swin=255, dwin=255,
                   ct_srv_src=3, ct_state_ttl=2, ct_dst_ltm=1, ct_src_ltm=1, ct_srv_dst=3)
attack_flow = dict(dur=0.0, spkts=500, dpkts=0, sbytes=50000, dbytes=0, rate=9999.0,
                   sttl=128, dttl=0, sload=99999.0, dload=0.0, sloss=100, dloss=0,
                   sinpkt=0.0, dinpkt=0.0, sjit=0.0, djit=0.0, swin=0, dwin=0,
                   ct_srv_src=50, ct_state_ttl=0, ct_dst_ltm=50, ct_src_ltm=50, ct_srv_dst=50)

for flow, label, expect_threat in [(normal_flow,"Normal",False),(attack_flow,"Attack",True)]:
    feats = extract_network_features(flow)
    r = det.predict("network", feats)
    flag = "✓" if r["is_threat"] == expect_threat else "✗"
    if r["is_threat"] != expect_threat:
        ok = False
    print(f"  {flag} [{r['threat_category']:12}] conf={r['confidence_score']:.3f}  {label} flow")

# ── 3. Cyberbullying ──────────────────────────────────────────────
print("\n[ Cyberbullying ]")
safe_cb     = [10.0, 1.0, 0.0, 0.8]
bullying_cb = [50.0, 40.0, 1.0, 0.2]

for stats, label, expect_threat in [(safe_cb,"Friendly",False),(bullying_cb,"Bullying",True)]:
    feats = extract_cyberbullying_features({
        "total_messages": stats[0], "aggressive_count": stats[1],
        "intent_to_harm": stats[2], "peerness": stats[3]
    })
    r = det.predict("cyberbullying", feats)
    flag = "✓" if r["is_threat"] == expect_threat else "✗"
    if r["is_threat"] != expect_threat:
        ok = False
    print(f"  {flag} [{r['threat_category']:12}] conf={r['confidence_score']:.3f}  {label} interaction")

print("\n" + "=" * 58)
if ok:
    print("  ✅ ALL TESTS PASSED — Models are working correctly.")
else:
    print("  ⚠  SOME TESTS FAILED — Review output above.")
print("=" * 58)
sys.exit(0 if ok else 1)
