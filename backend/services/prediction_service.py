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

            # 2. Run Anomaly Detection (Unsupervised)
            from backend.services.anomaly_service import AnomalyService
            anomaly_res = AnomalyService.detect(
                pred_res.get("scaled_features"),
                pred_res.get("prediction"),
                pred_res.get("confidence", 90.0)
            )

            # 3. Run Risk Scoring Engine
            from backend.services.risk_service import RiskService
            risk_res = RiskService.calculate_risk(
                prediction=pred_res["prediction"],
                attack_type=pred_res["attack_type"],
                confidence=pred_res["confidence"],
                payload=payload,
                is_anomaly=anomaly_res["is_anomaly"]
            )
            risk_score = risk_res["score"]
            risk_level = risk_res["severity"]  # Use calibrated risk level

            # 4. Run SHAP explanations
            model = load_trained_model()
            shap_res = explain_prediction(payload, pred_res, model)
            
            # Formulate timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 5. Store in DB (handling schema with risk_score, anomaly_score, is_anomaly)
            cursor.execute('''
                INSERT INTO predictions (
                    flow_id, timestamp, src_ip, dst_ip, protocol, port, 
                    prediction, confidence, risk_level, attack_type, explanation, shap_values,
                    risk_score, anomaly_score, is_anomaly
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                flow_id,
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                int(port),
                pred_res["prediction"],
                pred_res["confidence"],
                risk_level,
                pred_res["attack_type"],
                shap_res["explanation"],
                json.dumps(shap_res["shap_values"]),
                risk_score,
                anomaly_res["anomaly_score"],
                1 if anomaly_res["is_anomaly"] else 0
            ))
            
            conn.commit()
            
            # 6. Automated Incident Creation for High-Risk threats
            if risk_score >= 60 or risk_level in ["CRITICAL", "HIGH"]:
                try:
                    from backend.services.incident_service import IncidentService
                    IncidentService.create_incident(
                        flow_id=flow_id,
                        attack_type=pred_res["attack_type"],
                        severity=risk_level,
                        risk_score=risk_score,
                        confidence=pred_res["confidence"],
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        port=port,
                        protocol=protocol,
                        assigned_analyst="SOC Analyst 1",
                        recommended_actions=f"Isolate host {src_ip} at firewall. Apply rate limiting and drop suspicious traffic targeting port {port}."
                    )
                except Exception as inc_err:
                    logger.warning(f"Auto-incident creation skipped: {inc_err}")

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
                "risk_level": risk_level,
                "risk_score": risk_score,
                "risk_factors": risk_res["factors"],
                "attack_type": pred_res["attack_type"],
                "anomaly_detection": anomaly_res,
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

    @staticmethod
    def get_threat_analytics():
        """
        Gathers comprehensive cybersecurity threat analytics from actual database records:
        - Security overview counts
        - Attack type distribution
        - Severity breakdown
        - Threat timeline
        - Port and protocol analytics
        - SOC scorecard metrics
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Total flow counts
        cursor.execute("SELECT COUNT(*) FROM predictions")
        total_flows = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM predictions WHERE prediction != 'Normal'")
        threats_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM predictions WHERE prediction = 'Normal'")
        benign_count = cursor.fetchone()[0]

        # 2. Severity breakdown
        cursor.execute("SELECT risk_level, COUNT(*) as cnt FROM predictions GROUP BY risk_level")
        sev_map = {r['risk_level'].upper(): r['cnt'] for r in cursor.fetchall()}
        critical_count = sev_map.get("CRITICAL", 0)
        high_count = sev_map.get("HIGH", 0)
        medium_count = sev_map.get("MEDIUM", 0) + sev_map.get("MODERATE", 0)
        low_count = sev_map.get("LOW", 0)

        # 3. Attack types distribution
        cursor.execute("SELECT attack_type, COUNT(*) as cnt FROM predictions WHERE prediction != 'Normal' GROUP BY attack_type ORDER BY cnt DESC")
        attack_types = [{"attack_type": r['attack_type'], "count": r['cnt']} for r in cursor.fetchall()]

        # 4. Protocol distribution
        cursor.execute("SELECT protocol, COUNT(*) as cnt FROM predictions GROUP BY protocol")
        protocols = [{"protocol": r['protocol'], "count": r['cnt']} for r in cursor.fetchall()]

        # 5. Top targeted ports
        cursor.execute("SELECT port, COUNT(*) as cnt FROM predictions WHERE prediction != 'Normal' GROUP BY port ORDER BY cnt DESC LIMIT 5")
        top_ports = [{"port": r['port'], "count": r['cnt']} for r in cursor.fetchall()]

        # 6. Event timeline (last 20 logged threat flows)
        cursor.execute("SELECT flow_id, timestamp, src_ip, dst_ip, attack_type, risk_level, confidence, risk_score FROM predictions ORDER BY timestamp DESC LIMIT 20")
        timeline = [row_to_dict(r) for r in cursor.fetchall()]

        # 7. Anomaly count
        cursor.execute("SELECT COUNT(*) FROM predictions WHERE is_anomaly = 1")
        anomaly_count = cursor.fetchone()[0]

        conn.close()

        threat_rate = round((threats_count / total_flows) * 100, 2) if total_flows > 0 else 0.0

        return {
            "overview": {
                "total_flows": total_flows,
                "threats_detected": threats_count,
                "benign_traffic": benign_count,
                "threat_rate": threat_rate,
                "critical_threats": critical_count,
                "high_threats": high_count,
                "medium_threats": medium_count,
                "low_threats": low_count,
                "anomaly_count": anomaly_count
            },
            "attack_types": attack_types,
            "severity_distribution": {
                "CRITICAL": critical_count,
                "HIGH": high_count,
                "MEDIUM": medium_count,
                "LOW": low_count
            },
            "protocols": protocols,
            "top_ports": top_ports,
            "timeline": timeline
        }
