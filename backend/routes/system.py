from flask import Blueprint, request, jsonify
from backend.services.health_service import HealthService
from backend.services.audit_service import AuditService
from backend.services.prediction_service import PredictionService
from backend.AI.threat_analyzer import ThreatAnalyzer
from backend.utils.logger import logger

system_bp = Blueprint('system', __name__)

@system_bp.route('/api/system/health', methods=['GET'])
def get_system_health():
    """
    Endpoint GET /api/system/health
    Performs real functional health checks on Backend, ML Model, Database, AI Copilot, XAI Engine, Anomaly Detector.
    """
    try:
        health = HealthService.check_system_health()
        return jsonify({"status": "success", "data": health})
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "message": "Failed to query system health."}), 500

@system_bp.route('/api/audit/logs', methods=['GET'])
def get_audit_logs():
    """
    Endpoint GET /api/audit/logs
    Returns system audit logs.
    """
    limit = request.args.get('limit', 100, type=int)
    try:
        logs = AuditService.get_logs(limit=limit)
        return jsonify({"status": "success", "count": len(logs), "data": logs})
    except Exception as e:
        logger.error(f"Failed to fetch audit logs: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch audit logs."}), 500

@system_bp.route('/api/threat/analytics', methods=['GET'])
def get_threat_analytics():
    """
    Endpoint GET /api/threat/analytics
    Returns aggregated security analytics: threat overview, attack types, severity breakdown, timeline.
    """
    try:
        analytics = PredictionService.get_threat_analytics()
        return jsonify({"status": "success", "data": analytics})
    except Exception as e:
        logger.error(f"Failed to compile threat analytics: {e}")
        return jsonify({"status": "error", "message": "Failed to compile threat analytics."}), 500

@system_bp.route('/api/mitre/mapping', methods=['GET'])
def get_mitre_mappings():
    """
    Endpoint GET /api/mitre/mapping
    Returns structured MITRE ATT&CK mappings for known attack types.
    """
    attack_type = request.args.get('attack_type', None)
    
    mappings = {
        "DDoS": {
            "attack_type": "DDoS Ingress Exploit",
            "tactic": "Impact (TA0040)",
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "sub_technique": "T1498.001 - Direct Network Flood",
            "description": "Adversaries may perform Network Denial of Service attacks by sending high volumes of network traffic to saturate bandwidth, exhaust system state tables, or crash endpoints.",
            "mitigations": [
                {"id": "M1037", "name": "Filter Network Traffic", "description": "Deploy edge packet filters, rate limiters, or upstream scrubbing centers."},
                {"id": "M1030", "name": "Network Segmentation", "description": "Isolate high-traffic web ingress nodes behind segregated load balancers."}
            ]
        },
        "SSH-Patator": {
            "attack_type": "SSH Brute-Force Authentication",
            "tactic": "Credential Access (TA0006)",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "sub_technique": "T1110.001 - Password Guessing",
            "description": "Adversaries may use brute force techniques to systematically guess SSH credentials to acquire legitimate credentials and gain terminal access.",
            "mitigations": [
                {"id": "M1036", "name": "Account Lockout Policies", "description": "Configure fail2ban or PAM lockout after 5 consecutive failed attempts."},
                {"id": "M1032", "name": "Multi-Factor Authentication", "description": "Enforce MFA and SSH public-key cryptographic authentication."}
            ]
        },
        "PortScan": {
            "attack_type": "Port Scanner Reconnaissance",
            "tactic": "Discovery (TA0007)",
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "sub_technique": "N/A",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable daemon versions and listening ports.",
            "mitigations": [
                {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Drop sequential SYN sweeps and scan probes dynamically."},
                {"id": "M1042", "name": "Disable Unnecessary Services", "description": "Close unused ports and restrict administrative management interfaces to VPNs."}
            ]
        },
        "Suspicious": {
            "attack_type": "Anomalous Traffic Outlier",
            "tactic": "Initial Access (TA0001) / Defense Evasion (TA0005)",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "sub_technique": "N/A",
            "description": "Adversaries may attempt to exploit vulnerabilities or anomalous input variations in Internet-facing software to bypass detection.",
            "mitigations": [
                {"id": "M1016", "name": "Vulnerability Scanning", "description": "Conduct automated CVE audits and patch edge web application dependencies."},
                {"id": "M1050", "name": "Exploit Protection", "description": "Deploy Web Application Firewalls (WAF) to inspect abnormal payload lengths."}
            ]
        }
    }

    if attack_type and attack_type in mappings:
        return jsonify({"status": "success", "data": mappings[attack_type]})
    return jsonify({"status": "success", "data": mappings})
