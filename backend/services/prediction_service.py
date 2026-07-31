import json
from datetime import datetime
from backend.models.predict import predict_flow, load_trained_model
from backend.models.shap_explainer import explain_prediction
from backend.utils.helpers import get_db_connection, row_to_dict
from backend.utils.logger import logger

class PredictionService:
    @staticmethod
    def predict_and_store(flow_id, src_ip, dst_ip, protocol, port, payload, threshold=None):
        """
        Executes prediction model, runs SHAP explanations, and saves details to SQLite DB.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Check if record already exists
            cursor.execute("SELECT * FROM predictions WHERE flow_id = ?", (flow_id,))
            exists = cursor.fetchone()
            if exists:
                return row_to_dict(exists)
                
            # 1. Run classifier prediction
            pred_res = predict_flow(payload, threshold)
            
            # 2. Run SHAP explanations
            model = load_trained_model()
            shap_res = explain_prediction(payload, pred_res, model)
            
            # Formulate timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 3. Store in DB
            cursor.execute('''
                INSERT INTO predictions (
                    flow_id, timestamp, src_ip, dst_ip, protocol, port, 
                    prediction, confidence, risk_level, attack_type, explanation, shap_values
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                flow_id,
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                int(port),
                pred_res["prediction"],
                pred_res["confidence"],
                pred_res["risk_level"],
                pred_res["attack_type"],
                shap_res["explanation"],
                json.dumps(shap_res["shap_values"])
            ))
            
            conn.commit()
            
            # Update running metrics totals
            PredictionService.update_running_metrics(pred_res["prediction"])
            
            # Return compiled output
            return {
                "flow_id": flow_id,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "port": port,
                "prediction": pred_res["prediction"],
                "confidence": pred_res["confidence"],
                "risk_level": pred_res["risk_level"],
                "attack_type": pred_res["attack_type"],
                "explanation": shap_res["explanation"],
                "shap_values": shap_res["shap_values"]
            }
            
        except Exception as e:
            logger.error(f"Inference pipeline encountered error: {str(e)}")
            raise e
        finally:
            conn.close()

    @staticmethod
    def get_prediction_history(query=None, pred_filter=None, limit=100):
        """Fetches history of predicted network logs from SQLite database."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        sql = "SELECT * FROM predictions"
        params = []
        conditions = []
        
        if query:
            conditions.append("(flow_id LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)")
            q = f"%{query}%"
            params.extend([q, q, q, q])
            
        if pred_filter and pred_filter != 'all':
            conditions.append("prediction = ?")
            params.append(pred_filter.capitalize())
            
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
            
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        conn.close()
        
        return [row_to_dict(r) for r in rows]

    @staticmethod
    def update_running_metrics(prediction):
        """Increments traffic metrics totals in DB based on prediction results."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Get latest metric record
            cursor.execute("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 1")
            latest = cursor.fetchone()
            
            if latest:
                total = latest['total_packets'] + 1
                attacks = latest['total_attacks']
                normal = latest['normal_packets']
                malicious = latest['malicious_packets']
                
                if prediction == 'Normal':
                    normal += 1
                else:
                    attacks += 1
                    malicious += 1
                    
                # Threat level re-calibration based on attacks volume
                ratio = (attacks / total) * 100
                if ratio < 0.2:
                    threat = "LOW"
                elif ratio < 1.0:
                    threat = "MODERATE"
                elif ratio < 3.0:
                    threat = "HIGH"
                else:
                    threat = "CRITICAL"
                    
                cursor.execute('''
                    INSERT INTO metrics (timestamp, total_packets, total_attacks, normal_packets, malicious_packets, accuracy, fpr, threat_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    total,
                    attacks,
                    normal,
                    malicious,
                    latest['accuracy'],
                    latest['fpr'],
                    threat
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update running SOC metrics: {str(e)}")
        finally:
            conn.close()

    @staticmethod
    def get_aggregate_metrics():
        """Aggregates and compiles metrics metrics for dashboard charts."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        else:
            return {
                "total_packets": 284100,
                "total_attacks": 2284,
                "normal_packets": 281816,
                "malicious_packets": 2284,
                "accuracy": 99.42,
                "fpr": 0.11,
                "threat_level": "MODERATE"
            }
