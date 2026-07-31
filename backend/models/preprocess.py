import os
import pickle
import pandas as pd
import numpy as np
try:
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
from backend.config import Config
from backend.utils.logger import logger

# Clean column headers
def clean_columns(df):
    df.columns = df.columns.str.strip()
    return df

def clean_data(df):
    """
    Cleans DataFrame: handles infinity, nulls, and duplicate values.
    """
    df = clean_columns(df)
    
    # Replace infinity with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Drop rows with null values in target or key features
    df.dropna(inplace=True)
    
    # Drop duplicates to prevent model overfitting
    df.drop_duplicates(inplace=True)
    
    return df

def fit_save_preprocessors(df, features, target_col="Label"):
    """
    Fits and saves StandardScaler and LabelEncoder for the target variables.
    """
    os.makedirs(Config.MODEL_FOLDER, exist_ok=True)
    
    # Preprocess X (features)
    X = df[features].copy()
    scaler = StandardScaler()
    scaler.fit(X)
    
    scaler_path = os.path.join(Config.MODEL_FOLDER, 'scaler.pkl')
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    logger.info(f"Scaler successfully trained and saved to {scaler_path}")
    
    # Preprocess Y (Target Label)
    y = df[target_col].copy()
    label_encoder = LabelEncoder()
    label_encoder.fit(y)
    
    encoder_path = os.path.join(Config.MODEL_FOLDER, 'label_encoder.pkl')
    with open(encoder_path, 'wb') as f:
        pickle.dump(label_encoder, f)
    logger.info(f"Label encoder successfully trained and saved to {encoder_path}")
    
    return scaler, label_encoder

def load_preprocessors():
    """Loads pre-trained scaler and encoder serialization weights."""
    if not SKLEARN_AVAILABLE:
        raise ImportError("scikit-learn is not installed in this environment.")
        
    scaler_path = os.path.join(Config.MODEL_FOLDER, 'scaler.pkl')
    encoder_path = os.path.join(Config.MODEL_FOLDER, 'label_encoder.pkl')
    
    if not os.path.exists(scaler_path) or not os.path.exists(encoder_path):
        raise FileNotFoundError("Scaler or LabelEncoder not found. Please train the model first.")
        
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)
    with open(encoder_path, 'rb') as f:
        encoder = pickle.load(f)
        
    return scaler, encoder
