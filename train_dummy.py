import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

def generate_dummy_data(samples=500):
    """
    Generate synthetic data for training the dummy Random Forest model.
    Feature order:
    [
        duration, protocol, service_val, flag_val, src_bytes, dst_bytes,
        url_length, special_char_count, has_https, subdomain_count,
        sentiment_polarity, keyword_count
    ]
    Total 12 features.
    
    Classes:
    0: Safe
    1: Phishing
    2: Attack
    """
    np.random.seed(42)
    
    X = []
    y = []
    
    # Generate Normal traffic (Class 0)
    for _ in range(samples):
        # mix of network, url, and plain text
        ptype = np.random.choice(["network", "url", "text"])
        if ptype == "network":
            # Normal network traffic
            f = [
                np.random.exponential(1.0), # duration
                float(np.random.randint(1, 4)), # protocol
                float(np.random.randint(0, 5)), # service
                float(np.random.randint(0, 5)), # flag
                np.random.exponential(500), # src_bytes
                np.random.exponential(1000), # dst_bytes
                0., 0., 0., 0., # pad
                0., 0. # pad text
            ]
        elif ptype == "url":
            f = [
                0., 0., 0., 0., 0., 0., # pad
                np.random.normal(30, 10), # url length
                np.random.poisson(1), # special chars
                1.0, # has_https
                0.0, # subdomains
                0., 0. # pad
            ]
        else:
            f = [
                0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
                np.random.uniform(0.1, 1.0), # positive polarity
                0.0 # keywords
            ]
        X.append(f)
        y.append(0)
        
    # Generate Attack traffic (Class 2) - typically high network volume, weird protocols, or text threats
    for _ in range(samples // 2):
        # Network attack
        f = [
            np.random.exponential(10.0), # duration
            2.0, # UDP or ICMP
            float(np.random.randint(5, 10)), # odd service
            float(np.random.randint(5, 10)), # odd flag
            np.random.exponential(10000), # large src
            0.0, # zero dst
            0., 0., 0., 0., 0., 0.
        ]
        X.append(f)
        y.append(2)
        
        # Text threat
        f = [
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            np.random.uniform(-1.0, -0.5), # negative polarity
            float(np.random.poisson(3)) # lots of keywords
        ]
        X.append(f)
        y.append(2)

    # Generate Phishing URLs (Class 1)
    for _ in range(samples // 2):
        f = [
            0., 0., 0., 0., 0., 0.,
            np.random.normal(150, 50), # long url
            float(np.random.poisson(5)), # many special chars
            0.0, # no https
            float(np.random.poisson(3)), # high subdomains
            0., 0.
        ]
        X.append(f)
        y.append(1)

    return np.array(X), np.array(y)

def train_and_save():
    print("Generating synthetic data...")
    X, y = generate_dummy_data(1000)
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print("Training Random Forest Classifier...")
    # target > 95% accuracy on dummy data
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_scaled, y)
    
    acc = rf.score(X_scaled, y)
    print(f"Training accuracy: {acc * 100:.2f}%")
    
    # Save models
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler, "models/scaler.joblib")
    joblib.dump(rf, "models/rf_model.joblib")
    print("Saved scaler.joblib and rf_model.joblib to models/")

if __name__ == "__main__":
    train_and_save()
