import os
import pickle
import numpy as np
from backend.config import Config
from backend.utils.logger import logger

_ANOMALY_MODEL = None

class AnomalyService:
    """
    Unsupervised Anomaly Detection Layer using Isolation Forest.
    Operates independently from supervised classification to detect 
    statistical deviations and unknown anomalous flow patterns.
    """

    @staticmethod
    def load_model():
        global _ANOMALY_MODEL
        if _ANOMALY_MODEL is not None:
            return _ANOMALY_MODEL
            
        model_path = os.path.join(Config.MODEL_FOLDER, 'anomaly_detector.pkl')
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    _ANOMALY_MODEL = pickle.load(f)
                return _ANOMALY_MODEL
            except Exception as e:
                logger.warning(f"Could not load anomaly detector: {e}")
                
        return None

    @staticmethod
    def detect(scaled_features, supervised_pred="Normal", confidence=90.0):
        """
        Evaluates incoming flow vector against unsupervised Isolation Forest model.
        Returns:
            is_anomaly: bool
            anomaly_score: float (0.0 to 1.0)
            category: 'Known Attack' | 'Unknown / Anomalous Behavior' | 'Benign Behavior'
            decision_raw: float
        """
        model = AnomalyService.load_model()
        is_anomaly = False
        anomaly_score = 0.15
        decision_raw = 0.10

        if model is not None and scaled_features is not None:
            try:
                x_vec = np.array(scaled_features).reshape(1, -1)
                pred = model.predict(x_vec)[0]  # 1 for inlier, -1 for outlier
                score_raw = model.decision_function(x_vec)[0]
                decision_raw = float(score_raw)
                
                # Isolation Forest decision_function: lower means more anomalous (negative for outliers)
                # Map score_raw to 0.0 - 1.0 scale where higher is more anomalous
                # Standard decision_function usually ranges from -0.5 to +0.5
                norm_score = 1.0 / (1.0 + np.exp(score_raw * 5.0))
                anomaly_score = round(float(norm_score), 4)
                is_anomaly = bool(pred == -1)
            except Exception as e:
                logger.warning(f"Anomaly evaluation fallback: {e}")
                is_anomaly = False
                anomaly_score = 0.20

        # Categorize into 3 clear domains
        sup_lower = (supervised_pred or "").lower()
        if sup_lower in ["attack"] and confidence >= 70.0:
            category = "Known Attack"
        elif is_anomaly or (sup_lower == "suspicious"):
            category = "Unknown / Anomalous Behavior"
        else:
            category = "Benign Behavior"

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score * 100, 2),
            "category": category,
            "decision_raw": round(decision_raw, 4),
            "detector": "Isolation Forest (Unsupervised)"
        }
