from flask import Blueprint, request, send_file, jsonify
from backend.services.report_service import ReportService
from backend.utils.logger import logger

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/api/reports/download', methods=['GET'])
def download_report():
    """
    Endpoint GET /api/reports/download
    Generates and returns PDF, CSV, or JSON audits files.
    """
    fmt = request.args.get('format', 'pdf').lower()
    
    try:
        if fmt == 'pdf':
            filepath = ReportService.generate_pdf_report()
            mimetype = 'application/pdf'
            filename = 'threat_audit_report.pdf'
        elif fmt == 'csv':
            filepath = ReportService.generate_csv_report()
            mimetype = 'text/csv'
            filename = 'threat_audit_report.csv'
        elif fmt == 'json':
            filepath = ReportService.generate_json_report()
            mimetype = 'application/json'
            filename = 'threat_audit_report.json'
        else:
            return jsonify({"status": "error", "message": "Unsupported report format. Use PDF, CSV, or JSON."}), 400
            
        return send_file(
            filepath,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"Report generation route failed: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to compile report file."}), 500

@reports_bp.route('/api/reports/ai', methods=['GET'])
def download_ai_incident_report():
    """
    Endpoint GET /api/reports/ai?flow_id=FL-XXXX
    Generates and returns an AI Copilot PDF incident report.
    """
    flow_id = request.args.get('flow_id')
    if not flow_id:
        return jsonify({"status": "error", "message": "Missing flow_id parameter."}), 400
        
    from backend.utils.helpers import get_db_connection, row_to_dict
    from backend.AI.report_generator import AIReportGenerator
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM predictions WHERE flow_id = ?", (flow_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return jsonify({"status": "error", "message": f"Connection flow {flow_id} not found."}), 404
            
        flow_data = row_to_dict(row)
        filepath = AIReportGenerator.generate_incident_pdf(flow_data, filename=f"ai_report_{flow_id}.pdf")
        
        return send_file(
            filepath,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"ai_report_{flow_id}.pdf"
        )
    except Exception as e:
        logger.error(f"AI report download route failed: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to compile AI incident report."}), 500
