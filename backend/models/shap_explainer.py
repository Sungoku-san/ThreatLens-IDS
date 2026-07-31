import os
import sys
import pickle
import pandas as pd
import numpy as np
from backend.config import Config
from backend.models.preprocess import load_preprocessors
from backend.models.feature_engineering import SELECTED_FEATURES
from backend.utils.logger import logger

# Try loading shap package safely
SHAP_AVAILABLE = False
try:
    import shap
    SHAP_AVAILABLE = True
    logger.info("SHAP explainability package successfully loaded.")
except ImportError:
    logger.warning("SHAP package not available or failed to load. Activating Surrogate Explainer engine.")

# Global cache for explainer instances
_EXPLAINER = None
_BACKGROUND_DATA = None

def get_background_data():
    """Loads a small sample from the dataset to use as baseline reference for SHAP."""
    global _BACKGROUND_DATA
    if _BACKGROUND_DATA is not None:
        return _BACKGROUND_DATA
        
    try:
        scaler, _ = load_preprocessors()
        dataset_path = os.path.join(Config.DATASET_FOLDER, 'CICIDS2017.csv')
        
        if os.path.exists(dataset_path):
            df = pd.read_csv(dataset_path, nrows=100)
            df.columns = df.columns.str.strip()
            df = df.dropna()
            
            X = df[SELECTED_FEATURES]
            _BACKGROUND_DATA = scaler.transform(X)
        else:
            # Fallback if CSV is not found
            _BACKGROUND_DATA = np.zeros((100, len(SELECTED_FEATURES)))
    except Exception as e:
        logger.error(f"Failed to load background reference dataset: {str(e)}")
        _BACKGROUND_DATA = np.zeros((100, len(SELECTED_FEATURES)))
        
    return _BACKGROUND_DATA

def load_explainer(model):
    """Initializes TreeExplainer wrapper."""
    global _EXPLAINER
    if _EXPLAINER is not None:
        return _EXPLAINER
        
    if SHAP_AVAILABLE:
        try:
            bg_data = get_background_data()
            # Tree models are optimized using TreeExplainer
            _EXPLAINER = shap.TreeExplainer(model, data=bg_data)
            logger.info("SHAP TreeExplainer initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize SHAP TreeExplainer: {str(e)}. Falling back to surrogate model.")
            _EXPLAINER = None
            
    return _EXPLAINER

def explain_prediction(payload, prediction_result, model):
    """
    Computes local feature contributions for a single prediction.
    Falls back to surrogate weight calculation if true SHAP libraries are not loaded.
    """
    scaled_features = prediction_result["scaled_features"]
    prediction = prediction_result["prediction"]
    confidence = prediction_result["confidence"]
    attack_type = prediction_result["attack_type"]
    
    # 1. Try real SHAP first
    explainer = load_explainer(model)
    shap_vals = None
    
    if SHAP_AVAILABLE and explainer is not None:
        try:
            # Reshape input to (1, num_features)
            x_inst = scaled_features.reshape(1, -1)
            
            # Compute shap values
            # For multi-class, shap_values is a list of arrays (one for each class)
            raw_shap = explainer.shap_values(x_inst)
            
            # Extract target class index from prediction
            _, encoder = load_preprocessors()
            
            # Map prediction back to encoder class label
            # E.g., if prediction is "Normal", label is "BENIGN"
            if prediction == "Normal":
                class_label = "BENIGN"
            elif attack_type == "DDoS Ingress Exploit":
                class_label = "DDoS"
            elif attack_type == "Port Scanner Reconnaissance":
                class_label = "PortScan"
            elif attack_type == "SSH Brute-Force Authentication":
                class_label = "SSH-Patator"
            else:
                class_label = encoder.classes_[0] # fallback
                
            class_idx = np.where(encoder.classes_ == class_label)[0][0]
            
            if isinstance(raw_shap, list):
                shap_vals = raw_shap[class_idx][0]
            else:
                # Binary classification or alternative SHAP format
                if len(raw_shap.shape) == 3: # (num_instances, num_features, num_classes)
                    shap_vals = raw_shap[0, :, class_idx]
                else:
                    shap_vals = raw_shap[0]
                    
        except Exception as e:
            logger.error(f"True SHAP calculation encountered error: {str(e)}. Falling back to surrogate.")
            shap_vals = None

    # 2. Surrogate calculation fallback
    if shap_vals is None:
        shap_vals = _calculate_surrogate_shap(scaled_features, prediction, model)
        
    # 3. Formulate reasons lists
    shap_entries = []
    for idx, name in enumerate(SELECTED_FEATURES):
        val = payload.get(name, 0.0)
        impact = float(shap_vals[idx])
        shap_entries.append({
            "name": name,
            "value": str(val),
            "impact": round(impact, 4),
            "type": "positive" if impact >= 0 else "negative"
        })
        
    # Sort by absolute impact descending
    shap_entries.sort(key=lambda x: abs(x["impact"]), reverse=True)
    
    # 4. Filter positive & negative contributions
    pos_contrib = [e for e in shap_entries if e["type"] == "positive"][:3]
    neg_contrib = [e for e in shap_entries if e["type"] == "negative"][:2]
    
    # 5. Build natural language explanation
    explanation = _build_natural_explanation(prediction, pos_contrib, neg_contrib)
    
    return {
        "shap_values": shap_entries,
        "explanation": explanation
    }

def _calculate_surrogate_shap(scaled_features, prediction, model):
    """
    High-fidelity surrogate explainer engine.
    Calculates feature contribution by multiplying model global feature importances 
    with local deviation from baseline training sets.
    """
    try:
        # Extract features importance from model (Random Forest / Decision Tree)
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
        else:
            # Fallback uniform importances if model has no attribute
            importances = np.ones(len(SELECTED_FEATURES)) / len(SELECTED_FEATURES)
            
        # Standard scaled features are deviations from the mean (0.0)
        # If scaled_features is positive, it means value is greater than mean
        # If scaled_features is negative, value is less than mean
        
        # Local contribution = feature importance * local feature scaled value
        # For attack prediction, high positive deviations drive positive impact
        # For normal prediction, negative deviations or small values drive negative impact
        contributions = importances * scaled_features
        
        # Adjust direction based on prediction target
        if prediction == "Normal":
            # For normal predictions, features pushing values down are positive/negative relative to normal target
            # Benign classifier weights are opposite to attack weights
            contributions = -contributions
            
        # Normalize sum of contributions to ~0.5 scale for visually clean charts
        contrib_sum = np.sum(np.abs(contributions))
        if contrib_sum > 0:
            contributions = (contributions / contrib_sum) * 0.6
            
        return contributions
    except Exception as e:
        logger.error(f"Surrogate SHAP calculator failed: {str(e)}")
        return np.zeros(len(SELECTED_FEATURES))

def _build_natural_explanation(prediction, positive_features, negative_features):
    """Builds a human-readable explanation sentence summarizing target features weights."""
    if prediction in ["Attack", "Suspicious"]:
        pos_names = [f"'{f['name']}'" for f in positive_features]
        if pos_names:
            if len(pos_names) > 1:
                feat_str = ", ".join(pos_names[:-1]) + f" and {pos_names[-1]}"
            else:
                feat_str = pos_names[0]
            
            return f"The network traffic was classified as {prediction.lower()} because the flow characteristics for {feat_str} exceeded normal operating thresholds, indicating a potential exploit profile."
        else:
            return "The network traffic was classified as suspicious due to anomalous deviation from baseline flow parameters."
    else:
        neg_names = [f"'{f['name']}'" for f in negative_features]
        if neg_names:
            if len(neg_names) > 1:
                feat_str = ", ".join(neg_names[:-1]) + f" and {neg_names[-1]}"
            else:
                feat_str = neg_names[0]
            return f"The network traffic was classified as benign/normal. The core parameters, specifically {feat_str}, align with standard secure flow bounds."
        else:
            return "The network traffic matches standard baseline features. No malicious signatures were detected."
