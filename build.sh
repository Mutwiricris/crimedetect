#!/usr/bin/env bash
# build.sh — runs once during Render's build phase
# Installs deps and trains models onto the persistent disk IF they don't exist yet.
# This means models survive between deploys (only retrain if missing).

set -e

echo "=== Build: Installing dependencies ==="
pip install -r requirements.txt

MODELS_DIR="${MODELS_DIR:-models}"

if [ -f "$MODELS_DIR/url_model.joblib" ] && \
   [ -f "$MODELS_DIR/net_model.joblib" ] && \
   [ -f "$MODELS_DIR/cb_model.joblib" ]; then
  echo "=== Build: Models already exist on persistent disk — skipping training ==="
else
  echo "=== Build: No models found. Running training (this will take ~10-20 min) ==="
  python train.py
  echo "=== Build: Training complete ==="
fi
