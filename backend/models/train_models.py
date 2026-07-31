import os
import sys
import time
import pickle
import pandas as pd
import numpy as np
from datetime import datetime

# Adjust python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
import xgboost as xgb
import lightgbm as lgb

from backend.config import Config
from backend.models.preprocess import clean_data, fit_save_preprocessors
from backend.models.feature_engineering import get_selected_features
from backend.models.evaluate_models import evaluate_classifier
from backend.models.compare_models import ModelComparisonPlotter
from backend.models.save_best_model import serialize_best_model
from backend.utils.logger import logger
from backend.utils.helpers import get_db_connection, init_db

def train_and_evaluate_all():
    logger.info("Starting Enterprise Multi-Model Training and Evaluation Pipeline...")
    
    # 1. Initialize SQLite Database
    init_db()
    
    # 2. Locate and load dataset
    dataset_path = os.path.join(Config.DATASET_FOLDER, 'CICIDS2017.csv')
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found at {dataset_path}. Please place CICIDS2017.csv in the dataset directory.")
        return False
        
    df = pd.read_csv(dataset_path)
    logger.info(f"Loaded dataset: {len(df)} rows.")
    
    # Clean data
    df = clean_data(df)
    logger.info(f"Cleaned dataset: {len(df)} rows remaining.")
    
    features = get_selected_features()
    logger.info(f"Features selected for training: {features}")
    
    # Fit and save preprocessors
    scaler, encoder = fit_save_preprocessors(df, features)
    
    X = scaler.transform(df[features])
    y = encoder.transform(df["Label"])
    num_classes = len(encoder.classes_)
    logger.info(f"Target classes: {list(encoder.classes_)} (count: {num_classes})")
    
    # Train / Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    logger.info(f"Split data: {X_train.shape[0]} train rows, {X_test.shape[0]} test rows.")
    
    # Initialize classifiers
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, solver='lbfgs', random_state=42),
        "XGBoost": xgb.XGBClassifier(n_estimators=100, max_depth=6, random_state=42, eval_metric='mlogloss', n_jobs=-1),
        "LightGBM": lgb.LGBMClassifier(n_estimators=100, max_depth=6, random_state=42, verbose=-1, n_jobs=-1)
    }
    
    results = []
    confusion_matrices = {}
    feature_importances = {}
    
    best_f1 = 0.0
    best_model_name = ""
    best_model_obj = None
    
    for name, clf in models.items():
        logger.info(f"Training model: {name}...")
        
        # Measure Training Time
        start_train = time.time()
        clf.fit(X_train, y_train)
        train_time = time.time() - start_train
        
        # Evaluate model metrics
        logger.info(f"Evaluating model: {name}...")
        eval_metrics = evaluate_classifier(clf, X_test, y_test, num_classes=num_classes)
        
        # Feature importances mapping
        importances = {}
        if hasattr(clf, "feature_importances_"):
            importances = dict(zip(features, [float(v) for v in clf.feature_importances_]))
        elif hasattr(clf, "coef_"):
            # Logistic Regression coefficients average absolute weights
            coef_abs = np.mean(np.abs(clf.coef_), axis=0)
            importances = dict(zip(features, [float(v) for v in coef_abs]))
            
        feature_importances[name] = importances
        confusion_matrices[name] = eval_metrics["confusion_matrix"]
        
        # Compile result metrics
        model_result = {
            "model_name": name,
            "accuracy": eval_metrics["accuracy"],
            "precision": eval_metrics["precision"],
            "recall": eval_metrics["recall"],
            "f1_score": eval_metrics["f1_score"],
            "roc_auc": eval_metrics["roc_auc"],
            "training_time": train_time,
            "prediction_time": eval_metrics["prediction_time"]
        }
        results.append(model_result)
        logger.info(f"Results for {name}: F1={model_result['f1_score']:.4f}, Accuracy={model_result['accuracy']:.4f}")
        
        # Track best model based on F1-Score
        if model_result["f1_score"] > best_f1:
            best_f1 = model_result["f1_score"]
            best_model_name = name
            best_model_obj = clf
            
    # Save results to comparison DataFrame and write CSV
    results_df = pd.DataFrame(results)
    csv_path = os.path.join(Config.MODEL_FOLDER, 'model_results.csv')
    results_df.to_csv(csv_path, index=False)
    logger.info(f"Saved performance metrics table to {csv_path}")
    
    # Save best model to disk (best_model.pkl and model.pkl for compatibility)
    serialize_best_model(best_model_name, best_model_obj)
    
    # Generate and save performance visualization plots
    ModelComparisonPlotter.generate_comparison_plots(
        results_df=results_df,
        confusion_matrices=confusion_matrices,
        feature_importances=feature_importances,
        y_test=y_test,
        X_test=X_test,
        models_dict=models
    )
    logger.info("Successfully completed model training and visual comparative plotting.")
    
    # Update SQLite database model statistics metadata
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Deactivate older models
    cursor.execute("UPDATE model_info SET active = 0")
    
    # Insert new models statistics
    for res in results:
        is_best = 1 if res["model_name"] == best_model_name else 0
        cursor.execute('''
            INSERT INTO model_info (model_name, accuracy, precision, recall, f1_score, roc_auc, trained_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            res["model_name"],
            res["accuracy"],
            res["precision"],
            res["recall"],
            res["f1_score"],
            res["roc_auc"],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            is_best
        ))
        
    conn.commit()
    conn.close()
    logger.info("Updated SQLite database tables with model comparison information.")
    return True

if __name__ == '__main__':
    train_and_evaluate_all()
