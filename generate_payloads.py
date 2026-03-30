import pandas as pd
import json
from src.features import URL_FEATURE_NAMES, NET_FEATURE_NAMES, CB_FEATURE_NAMES

def get_net_attack():
    df = pd.read_csv("Datasets/2. Network Intrusion & Attack Monitoring/UNSW_NB15_training-set.csv")
    row = df[df['label'] == 1].iloc[0]
    payload = {k: float(row[k]) for k in NET_FEATURE_NAMES}
    return json.dumps({"type": "network", "data": payload})

def get_cb_attack():
    df = pd.read_csv("Datasets/A Comprehensive Dataset for Automated Cyberbullying Detection/6. CB_Labels.csv")
    row = df[df['CB_Label'] == 1].iloc[0]
    payload = {
        "total_messages": float(row["Total_messages"]),
        "aggressive_count": float(row["Aggressive_Count"]),
        "intent_to_harm": float(row["Intent_to_Harm"]),
        "peerness": float(row["Peerness"])
    }
    return json.dumps({"type": "cyberbullying", "data": payload})

print("NET_PAYLOAD='" + get_net_attack() + "'")
print("CB_PAYLOAD='" + get_cb_attack() + "'")
