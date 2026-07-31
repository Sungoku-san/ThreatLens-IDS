from flask import Blueprint, jsonify
from backend.services.prediction_service import PredictionService
from backend.utils.helpers import get_db_connection, row_to_dict
from backend.utils.logger import logger

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/api/dashboard', methods=['GET'])
def get_dashboard_metrics():
    """
    Endpoint GET /api/dashboard
    Returns accumulated SOC packets metrics.
    """
    try:
        metrics = PredictionService.get_aggregate_metrics()
        return jsonify({"status": "success", "data": metrics})
    except Exception as e:
        logger.error(f"Failed to fetch dashboard metrics: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to compile metrics."}), 500

@dashboard_bp.route('/api/recent-attacks', methods=['GET'])
def get_recent_attacks():
    """
    Endpoint GET /api/recent-attacks
    Returns last 5 malicious threat alerts.
    """
    try:
        # Attacks pred filter
        results = PredictionService.get_prediction_history(pred_filter="Attack", limit=10)
        return jsonify({"status": "success", "data": results})
    except Exception as e:
        logger.error(f"Failed to fetch recent threat alerts: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to fetch threat alerts."}), 500

@dashboard_bp.route('/api/model-info', methods=['GET'])
def get_model_info():
    """
    Endpoint GET /api/model-info
    Returns information about active machine learning model metrics.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM model_info WHERE active = 1 ORDER BY trained_at DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            return jsonify({"status": "success", "data": dict(row)})
        else:
            return jsonify({"status": "error", "message": "No active model registered."}), 404
    except Exception as e:
        logger.error(f"Failed to load active model details: {str(e)}")
        return jsonify({"status": "error", "message": "Database query failed."}), 500
    finally:
        conn.close()

@dashboard_bp.route('/api/health', methods=['GET'])
def check_health():
    """
    Endpoint GET /api/health
    Basic service health check endpoint.
    """
    return jsonify({
        "status": "success",
        "service": "AI-Based Intrusion Detection System API",
        "state": "UP",
        "version": "1.0.4"
    })

@dashboard_bp.route('/api/settings', methods=['GET'])
def get_api_settings():
    """
    Endpoint GET /api/settings
    Checks if Gemini and Groq API keys are set.
    """
    import os
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    groq_key = os.environ.get("GROQ_API_KEY", "")
    return jsonify({
        "status": "success",
        "data": {
            "gemini_api_key_set": bool(gemini_key) and not gemini_key.startswith("test_"),
            "groq_api_key_set": bool(groq_key) and not groq_key.startswith("test_")
        }
    })

@dashboard_bp.route('/api/settings', methods=['POST'])
def save_api_settings():
    """
    Endpoint POST /api/settings
    Saves API keys to .env and env vars.
    """
    from flask import request
    from backend.utils.helpers import update_env_keys
    
    data = request.get_json() or {}
    gemini_key = data.get("gemini_api_key", None)
    groq_key = data.get("groq_api_key", None)
    
    try:
        update_env_keys(gemini_key=gemini_key, groq_key=groq_key)
        return jsonify({
            "status": "success",
            "message": "API keys successfully updated."
        })
    except Exception as e:
        logger.error(f"Failed to update API configurations: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to save settings: {str(e)}"
        }), 500

