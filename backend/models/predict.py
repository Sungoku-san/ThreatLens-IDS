import os
import pickle
import numpy as np
import pandas as pd
from backend.config import Config
from backend.models.preprocess import load_preprocessors
from backend.models.feature_engineering import map_payload_to_features, SELECTED_FEATURES
from backend.utils.logger import logger

# Lazy model loader
_MODEL = None

def load_trained_model():
    """Loads saved serialized classifier weights."""
    global _MODEL
    if _MODEL is not None:
        return _MODEL
        
    model_path = os.path.join(Config.MODEL_FOLDER, 'model.pkl')
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found at {model_path}. Train the model first.")
        
    with open(model_path, 'rb') as f:
        _MODEL = pickle.load(f)
    return _MODEL

def predict_flow(payload, threshold=None):
    """
    Predicts threat status of a single incoming network flow packet.
    """
    if threshold is None:
        threshold = Config.DEFAULT_THRESHOLD
        
    # 1. Load scaler, label encoder, and classifier
    scaler, encoder = load_preprocessors()
    model = load_trained_model()
    
    # 2. Map payload keys to official SELECTED_FEATURES
    mapped_features = map_payload_to_features(payload)
    
    # Convert to numeric DataFrame row
    x_df = pd.DataFrame([mapped_features])
    
    # 3. Standard scale values
    x_scaled = scaler.transform(x_df[SELECTED_FEATURES])
    
    # 4. Predict probabilities
    probs = model.predict_proba(x_scaled)[0]
    pred_idx = np.argmax(probs)
    confidence = float(probs[pred_idx])
    
    # Decode target integer class name
    class_label = encoder.classes_[pred_idx]
    
    # Map benign/attacks
    if class_label == "BENIGN":
        prediction = "Normal"
        attack_type = "None"
        risk_level = "Low"
    else:
        prediction = "Attack"
        # Extract specific attack type name
        if class_label == "DDoS":
            attack_type = "DDoS Ingress Exploit"
            risk_level = "Critical"
        elif class_label == "PortScan":
            attack_type = "Port Scanner Reconnaissance"
            risk_level = "High"
        elif class_label == "SSH-Patator":
            attack_type = "SSH Brute-Force Authentication"
            risk_level = "High"
        else:
            attack_type = "Suspicious Intrusion Node"
            risk_level = "Moderate"
            
    # Risk adjustments based on threshold logic
    # If confidence of benign is less than threshold, classify as suspicious/attack
    benign_idx = np.where(encoder.classes_ == "BENIGN")[0][0]
    benign_prob = probs[benign_idx]
    
    if prediction == "Normal" and (1 - benign_prob) > threshold:
        prediction = "Suspicious"
        attack_type = "Anomalous Traffic Outlier"
        risk_level = "Moderate"
        confidence = float(1 - benign_prob)
        
    return {
        "prediction": prediction,
        "confidence": round(confidence * 100, 2),
        "attack_type": attack_type,
        "risk_level": risk_level,
        "feature_values": mapped_features,
        "scaled_features": x_scaled[0]
    }
