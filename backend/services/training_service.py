import os
import pandas as pd
from backend.config import Config
from backend.models.train_models import train_and_evaluate_all
from backend.utils.logger import logger
from backend.utils.helpers import get_db_connection

class TrainingService:
    @staticmethod
    def trigger_retraining():
        """
        Triggers the machine learning multi-model comparison training pipeline.
        Returns the comparison results and status.
        """
        logger.info("TrainingService: Retraining pipeline triggered by API.")
        success = train_and_evaluate_all()
        if not success:
            return {"status": "error", "message": "Model training failed. Verify that the training dataset exists."}
            
        # Read the generated CSV comparison table
        csv_path = os.path.join(Config.MODEL_FOLDER, 'model_results.csv')
        results = []
        if os.path.exists(csv_path):
            try:
                df = pd.read_csv(csv_path)
                results = df.to_dict(orient='records')
            except Exception as e:
                logger.error(f"TrainingService: Failed to parse model_results.csv: {str(e)}")
            
        return {
            "status": "success",
            "message": "All five models successfully trained and compared.",
            "metrics": results
        }

    @staticmethod
    def get_model_history():
        """
        Retrieves historical model comparison stats from the SQLite database.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id, model_name, accuracy, precision, recall, f1_score, roc_auc, trained_at, active FROM model_info ORDER BY id DESC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"TrainingService: Failed to load model_info logs: {str(e)}")
            return []
        finally:
            conn.close()
