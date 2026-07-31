from backend.utils.helpers import get_db_connection, row_to_dict
from backend.utils.logger import logger

class ShapService:
    @staticmethod
    def get_shap_for_flow(flow_id):
        """
        Retrieves pre-calculated SHAP explainability insights from the database for a specific flow.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM predictions WHERE flow_id = ?", (flow_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        data = row_to_dict(row)
        return {
            "flow_id": data["flow_id"],
            "prediction": data["prediction"],
            "confidence": data["confidence"],
            "risk_level": data["risk_level"],
            "attack_type": data["attack_type"],
            "explanation": data["explanation"],
            "shap_values": data["shap_values"]
        }
        
    @staticmethod
    def get_global_importance():
        """
        Returns average global feature weights for model explainability dashboards.
        """
        # Hardcoded relative global importances mapping based on train evaluations
        return {
            "features": ['dst_port', 'packet_rate', 'flow_duration', 'packet_size', 'payload_weight', 'syn_flags'],
            "values": [0.38, 0.32, 0.28, 0.22, 0.18, 0.14]
        }
