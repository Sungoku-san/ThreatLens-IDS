from flask import Blueprint, request, jsonify
from backend.services.threat_service import ThreatService
from backend.utils.logger import logger

threat_bp = Blueprint('threat', __name__)

@threat_bp.route('/api/threat', methods=['GET'])
def get_threat_intel():
    """
    Endpoint GET /api/threat?ip=x.x.x.x&port=xx
    Gathers compiled threat intelligence.
    """
    ip = request.args.get('ip', '').strip()
    port = request.args.get('port', None)
    if not ip:
        return jsonify({"status": "error", "message": "Missing required 'ip' query parameter."}), 400
        
    try:
        intel = ThreatService.compile_threat_intelligence(ip, port)
        logger.info(f"Threat API: Compiled threat intelligence analysis for IP: {ip}")
        return jsonify({"status": "success", "data": intel})
    except Exception as e:
        logger.error(f"Threat Intel API route error: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to compile threat intelligence."}), 500
