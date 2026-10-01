from flask import Blueprint, request, jsonify
from backend.services.incident_service import IncidentService
from backend.utils.logger import logger

incidents_bp = Blueprint('incidents', __name__)

@incidents_bp.route('/api/incidents', methods=['GET'])
def list_incidents():
    """
    Endpoint GET /api/incidents
    Lists security incidents with optional status, severity, and search filtering.
    """
    status = request.args.get('status', None)
    severity = request.args.get('severity', None)
    search = request.args.get('q', None)
    limit = request.args.get('limit', 100, type=int)

    try:
        incidents = IncidentService.get_incidents(status=status, severity=severity, search=search, limit=limit)
        return jsonify({
            "status": "success",
            "count": len(incidents),
            "data": incidents
        })
    except Exception as e:
        logger.error(f"Failed to fetch incidents: {e}")
        return jsonify({"status": "error", "message": "Failed to query incidents database."}), 500

@incidents_bp.route('/api/incidents/stats', methods=['GET'])
def get_incident_stats():
    """
    Endpoint GET /api/incidents/stats
    Returns incident summary statistics (active load, counts by status and severity).
    """
    try:
        stats = IncidentService.get_statistics()
        return jsonify({"status": "success", "data": stats})
    except Exception as e:
        logger.error(f"Failed to fetch incident statistics: {e}")
        return jsonify({"status": "error", "message": "Failed to compile incident statistics."}), 500

@incidents_bp.route('/api/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    """
    Endpoint GET /api/incidents/<incident_id>
    Fetches full investigation details for a specific incident.
    """
    try:
        inc = IncidentService.get_incident_by_id(incident_id)
        if not inc:
            return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found."}), 404
        return jsonify({"status": "success", "data": inc})
    except Exception as e:
        logger.error(f"Failed to get incident {incident_id}: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch incident details."}), 500

@incidents_bp.route('/api/incidents/<incident_id>', methods=['PATCH', 'PUT'])
def update_incident(incident_id):
    """
    Endpoint PATCH /api/incidents/<incident_id>
    Updates incident triage status, assigns analyst, or appends incident response notes.
    """
    data = request.get_json() or {}
    status = data.get('status')
    analyst = data.get('assigned_analyst')
    notes = data.get('notes')

    if not status:
        return jsonify({"status": "error", "message": "Missing 'status' in request body."}), 400

    try:
        updated = IncidentService.update_incident_status(incident_id, status, assigned_analyst=analyst, notes=notes)
        if not updated:
            return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found."}), 404
        return jsonify({"status": "success", "message": f"Incident {incident_id} updated.", "data": updated})
    except ValueError as ve:
        return jsonify({"status": "error", "message": str(ve)}), 422
    except Exception as e:
        logger.error(f"Failed to update incident {incident_id}: {e}")
        return jsonify({"status": "error", "message": "Failed to update incident."}), 500

@incidents_bp.route('/api/incidents', methods=['POST'])
def create_incident():
    """
    Endpoint POST /api/incidents
    Manually creates a security incident from analyst investigation.
    """
    data = request.get_json() or {}
    required = ["attack_type", "severity", "src_ip"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"status": "error", "message": f"Missing required fields: {missing}"}), 400

    try:
        inc = IncidentService.create_incident(
            flow_id=data.get("flow_id", "MANUAL-ENTRY"),
            attack_type=data.get("attack_type"),
            severity=data.get("severity", "HIGH"),
            risk_score=data.get("risk_score", 75),
            confidence=data.get("confidence", 95.0),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip", "10.0.0.1"),
            port=data.get("port", 80),
            protocol=data.get("protocol", "TCP"),
            assigned_analyst=data.get("assigned_analyst", "SOC Analyst 1"),
            recommended_actions=data.get("recommended_actions")
        )
        return jsonify({"status": "success", "message": "Incident created.", "data": inc}), 201
    except Exception as e:
        logger.error(f"Failed to create manual incident: {e}")
        return jsonify({"status": "error", "message": "Failed to create incident."}), 500
