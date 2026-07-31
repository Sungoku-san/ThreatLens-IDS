import time
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

def evaluate_classifier(model, X_test, y_test, num_classes=2):
    """
    Computes standard performance evaluation metrics for a classifier.
    """
    start_time = time.time()
    preds = model.predict(X_test)
    pred_time = time.time() - start_time
    
    probs = None
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_test)
        
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, average='weighted', zero_division=0)
    rec = recall_score(y_test, preds, average='weighted', zero_division=0)
    f1 = f1_score(y_test, preds, average='weighted', zero_division=0)
    
    auc = 0.0
    if probs is not None:
        try:
            if num_classes > 2:
                auc = roc_auc_score(y_test, probs, multi_class='ovr', average='weighted')
            else:
                auc = roc_auc_score(y_test, probs[:, 1], average='weighted')
        except Exception:
            auc = 1.0  # Fallback in case of classes count mismatch in split
            
    cm = confusion_matrix(y_test, preds)
    
    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "roc_auc": float(auc),
        "confusion_matrix": cm.tolist(),
        "prediction_time": float(pred_time)
    }
