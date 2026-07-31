from backend.utils.logger import logger

class ThreatAnalyzer:
    @staticmethod
    def analyze_threat(prediction, attack_type, confidence):
        """
        Runs analytical mapping on threat predictions to calculate severity, impact, 
        MITRE maps, and threat vectors.
        """
        if prediction == "Normal":
            return {
                "severity": "LOW",
                "likelihood": "LOW",
                "impact": "NONE",
                "mitre_technique": "N/A",
                "mitre_id": "N/A",
                "affected_services": "None",
                "ioc": []
            }
            
        # Classify severity
        if confidence > 90:
            severity = "CRITICAL" if "ddos" in attack_type.lower() else "HIGH"
        else:
            severity = "MODERATE"
            
        likelihood = "HIGH" if confidence > 80 else "MEDIUM"
        
        # Determine MITRE details
        if "ddos" in attack_type.lower():
            mitre_id = "T1498"
            mitre_technique = "Network Denial of Service"
            impact = "Denial of access to web application and services; exhaust CPU/RAM buffers."
            services = "Web Servers, Core Switch Interfaces"
        elif "brute" in attack_type.lower() or "ssh" in attack_type.lower():
            mitre_id = "T1110"
            mitre_technique = "Brute Force"
            impact = "Unauthorized account access; credentials compromise; lateral network movement."
            services = "SSH Services, PAM Authentication Panels"
        elif "scan" in attack_type.lower():
            mitre_id = "T1046"
            mitre_technique = "Network Service Scanning"
            impact = "Information disclosure; mapping of active ports and exploitable interfaces."
            services = "All External Mapped Nodes"
        else:
            mitre_id = "T1190"
            mitre_technique = "Exploit Public-Facing Application"
            impact = "System compromise; privilege escalation."
            services = "Quarantined Node Segments"
            
        return {
            "severity": severity,
            "likelihood": likelihood,
            "impact": impact,
            "mitre_technique": mitre_technique,
            "mitre_id": mitre_id,
            "affected_services": services,
            "ioc": ["High packet frequency signature", "Payload anomalies matches"]
        }
