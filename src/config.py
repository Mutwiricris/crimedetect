"""
Central configuration — reads from environment variables with safe defaults.
Copy .env.example to .env and set values before running.
"""
import os

# --- Security ---
API_KEY: str = os.getenv("API_KEY", "devkey")

# --- CORS ---
# Comma-separated list of allowed origins, e.g. "https://yourlaravel.app,http://localhost"
_origins_raw: str = os.getenv("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _origins_raw.split(",")]

# --- Server ---
PORT: int = int(os.getenv("PORT", "8000"))

# --- Models directory ---
MODELS_DIR: str = os.getenv("MODELS_DIR", "models")

# --- Dataset paths (used only during training) ---
DATASETS_DIR: str = os.getenv("DATASETS_DIR", "Datasets")

URL_DATASET: str = os.path.join(
    DATASETS_DIR,
    "phiusiil+phishing+url+dataset",
    "PhiUSIIL_Phishing_URL_Dataset.csv",
)

NET_DATASET: str = os.path.join(
    DATASETS_DIR,
    "2. Network Intrusion & Attack Monitoring",
    "UNSW_NB15_training-set.csv",
)

CB_DATASET: str = os.path.join(
    DATASETS_DIR,
    "A Comprehensive Dataset for Automated Cyberbullying Detection",
    "6. CB_Labels.csv",
)
