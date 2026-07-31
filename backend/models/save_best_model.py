import os
import shutil
import pickle
from backend.config import Config
from backend.utils.logger import logger

def serialize_best_model(model_name, model_object):
    """
    Saves the selected best-performing model to disk.
    Copies it to both best_model.pkl and model.pkl for system compatibility.
    """
    model_dir = Config.MODEL_FOLDER
    os.makedirs(model_dir, exist_ok=True)
    
    best_path = os.path.join(model_dir, 'best_model.pkl')
    compat_path = os.path.join(model_dir, 'model.pkl')
    
    try:
        with open(best_path, 'wb') as f:
            pickle.dump(model_object, f)
        logger.info(f"Saved best model ({model_name}) to {best_path}")
        
        # Copy for predict.py compatibility
        shutil.copyfile(best_path, compat_path)
        logger.info(f"Copied best model to active path: {compat_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save best model file: {str(e)}")
        return False
