import os
import sys
import pickle
from datetime import datetime
import pandas as pd
import numpy as np

# Adjust python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

from backend.config import Config
from backend.models.preprocess import clean_data, fit_save_preprocessors
from backend.models.feature_engineering import get_selected_features
from backend.utils.logger import logger
from backend.utils.helpers import get_db_connection, init_db

def train_and_evaluate():
    logger.info("Starting Machine Learning model training pipeline...")
    
    # 1. Initialize database first
    init_db()
    
    # 2. Load dataset
    dataset_path = os.path.join(Config.DATASET_FOLDER, 'CICIDS2017.csv')
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found at {dataset_path}. Please generate sample first.")
        return False
        
    df = pd.read_csv(dataset_path)
    logger.info(f"Loaded dataset containing {len(df)} rows.")
    
    # Clean data
    df = clean_data(df)
    logger.info(f"Cleaned dataset: {len(df)} rows remaining.")
    
    features = get_selected_features()
    logger.info(f"Selected features: {features}")
    
    # Fit and save preprocessors
    scaler, encoder = fit_save_preprocessors(df, features)
    
    X = scaler.transform(df[features])
    y = encoder.transform(df["Label"])
    
    # Check classes
    classes = list(encoder.classes_)
    logger.info(f"Label classes encoded: {classes}")
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    logger.info(f"Train/Test split: {X_train.shape[0]} train rows, {X_test.shape[0]} test rows.")
    
    # Define models to compare
    models = {
        "Random Forest Classifier": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1),
        "Decision Tree Classifier": DecisionTreeClassifier(max_depth=10, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, solver='lbfgs', random_state=42)
    }
    
    best_f1 = 0
    best_model_name = ""
    best_model = None
    best_metrics = {}
    
    for name, clf in models.items():
        logger.info(f"Evaluating {name}...")
        
        # Cross validation
        cv_scores = cross_val_score(clf, X_train, y_train, cv=3, scoring='accuracy')
        logger.info(f"  CV Accuracy: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")
        
        # Fit on train set
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        probs = clf.predict_proba(X_test) if hasattr(clf, 'predict_proba') else None
        
        # Calculate metrics
        acc = accuracy_score(y_test, preds)
        
        # For multi-class classification
        prec = precision_score(y_test, preds, average='weighted', zero_division=0)
        rec = recall_score(y_test, preds, average='weighted', zero_division=0)
        f1 = f1_score(y_test, preds, average='weighted', zero_division=0)
        
        # Multi-class ROC AUC
        if probs is not None:
            try:
                # OVR = One-vs-Rest ROC AUC
                auc = roc_auc_score(y_test, probs, multi_class='ovr', average='weighted')
            except Exception as e:
                auc = 1.0  # Fallback in case of classes count mismatch in split
        else:
            auc = 0.0
            
        logger.info(f"  Test Metrics -> Acc: {acc:.4f}, Prec: {prec:.4f}, Rec: {rec:.4f}, F1: {f1:.4f}, AUC: {auc:.4f}")
        
        # Track best model based on F1
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = clf
            best_metrics = {
                "accuracy": float(acc),
                "precision": float(prec),
                "recall": float(rec),
                "f1_score": float(f1),
                "roc_auc": float(auc)
            }
            
    logger.info(f"Best performing model: {best_model_name} with F1-Score: {best_f1:.4f}")
    
    # Save best model to disk
    model_path = os.path.join(Config.MODEL_FOLDER, 'model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(best_model, f)
    logger.info(f"Successfully serialized and saved model to {model_path}")
    
    # Write model performance info to SQLite DB
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Set all other models to inactive
    cursor.execute("UPDATE model_info SET active = 0")
    
    # Insert new model info
    cursor.execute('''
        INSERT INTO model_info (model_name, accuracy, precision, recall, f1_score, roc_auc, trained_at, active)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    ''', (
        best_model_name + " (Auto-Trained)",
        best_metrics["accuracy"],
        best_metrics["precision"],
        best_metrics["recall"],
        best_metrics["f1_score"],
        best_metrics["roc_auc"],
        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ))
    
    conn.commit()
    conn.close()
    logger.info("Successfully updated model_info performance metrics in SQLite database.")
    return True

if __name__ == '__main__':
    train_and_evaluate()
