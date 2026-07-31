# feature_engineering.py - Defines target parameters and headers map

# Selected standard feature set for training and real-time prediction pipeline
SELECTED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count"
]

def get_selected_features():
    """Returns list of selected network flow features."""
    return SELECTED_FEATURES

def map_payload_to_features(payload):
    """
    Maps incoming frontend JSON packet dictionary to standard feature list,
    handling column name whitespace mapping safely.
    """
    mapped = {}
    for feat in SELECTED_FEATURES:
        # Check standard key, stripped key, and lowercase keys
        val = 0
        for k, v in payload.items():
            if k.strip() == feat or k.lower().strip() == feat.lower():
                val = v
                break
        mapped[feat] = float(val) if val is not None else 0.0
    return mapped
