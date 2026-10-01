class RiskService:
    """
    Transparent, deterministic Cybersecurity Risk Scoring Engine.
    Calculates explainable risk scores (0-100) from verified factors:
    1. Base Attack Category Severity (max 40 pts)
    2. Classifier Confidence Contribution (max 25 pts)
    3. Traffic Flow & Packet Rate Dynamics (max 20 pts)
    4. Unsupervised Anomaly Detector Output (max 15 pts)
    """

    @staticmethod
    def calculate_risk(prediction, attack_type, confidence, payload=None, is_anomaly=False):
        factors = []
        score = 0

        attack_lower = (attack_type or "").lower()
        pred_lower = (prediction or "").lower()

        # 1. Base Attack Category Severity (0 - 40 pts)
        if "ddos" in attack_lower:
            base_pts = 40
            factors.append({
                "factor": "Volumetric Denial of Service exploit vector (DDoS)",
                "impact": "+40 pts",
                "type": "negative"
            })
        elif "ssh" in attack_lower or "brute" in attack_lower:
            base_pts = 35
            factors.append({
                "factor": "Credential brute-force authentication attempt (SSH)",
                "impact": "+35 pts",
                "type": "negative"
            })
        elif "port" in attack_lower or "scan" in attack_lower:
            base_pts = 25
            factors.append({
                "factor": "Network reconnaissance / port sweeping behavior",
                "impact": "+25 pts",
                "type": "negative"
            })
        elif pred_lower in ["attack", "suspicious"]:
            base_pts = 20
            factors.append({
                "factor": "Generic intrusion signature deviation",
                "impact": "+20 pts",
                "type": "negative"
            })
        else:
            base_pts = 0
            factors.append({
                "factor": "Standard benign protocol traffic profile",
                "impact": "+0 pts",
                "type": "positive"
            })
        score += base_pts

        # 2. Classifier Confidence Contribution (0 - 25 pts)
        if pred_lower != "normal":
            conf_pts = int(round((float(confidence) / 100.0) * 25))
            score += conf_pts
            factors.append({
                "factor": f"High supervised model confidence ({float(confidence):.1f}%)",
                "impact": f"+{conf_pts} pts",
                "type": "negative"
            })
        else:
            factors.append({
                "factor": f"High benign model confidence ({float(confidence):.1f}%)",
                "impact": "0 pts",
                "type": "positive"
            })

        # 3. Traffic Flow & Packet Rate Dynamics (0 - 20 pts)
        if payload:
            packet_rate = float(payload.get("Flow Packets/s", payload.get("packet_rate", 0)))
            syn_flags = float(payload.get("SYN Flag Count", payload.get("syn_flags", 0)))
            ack_flags = float(payload.get("ACK Flag Count", payload.get("ack_flags", 0)))
            dst_port = int(payload.get("Destination Port", payload.get("port", 80)))

            if packet_rate > 500:
                score += 10
                factors.append({
                    "factor": f"Abnormal packet surge ({packet_rate:.0f} pkts/s)",
                    "impact": "+10 pts",
                    "type": "negative"
                })
            elif packet_rate > 80:
                score += 5
                factors.append({
                    "factor": f"Elevated packet transfer frequency ({packet_rate:.0f} pkts/s)",
                    "impact": "+5 pts",
                    "type": "negative"
                })

            if syn_flags > 0 and ack_flags == 0:
                score += 10
                factors.append({
                    "factor": "Asymmetric TCP SYN flags without ACK response (SYN Flood signature)",
                    "impact": "+10 pts",
                    "type": "negative"
                })

            if dst_port in [22, 23, 3389] and pred_lower != "normal":
                factors.append({
                    "factor": f"Targeting critical administrative access port ({dst_port})",
                    "impact": "Flagged",
                    "type": "negative"
                })

        # 4. Unsupervised Anomaly Detector Output (0 - 15 pts)
        if is_anomaly:
            score += 15
            factors.append({
                "factor": "Unsupervised Isolation Forest flagged statistical feature outlier",
                "impact": "+15 pts",
                "type": "negative"
            })

        # Clamp between 0 and 100
        final_score = max(0, min(100, score))

        # Severity Classification
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 35:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "score": final_score,
            "severity": severity,
            "factors": factors
        }
