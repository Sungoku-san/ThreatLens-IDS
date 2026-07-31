from flask import Blueprint, jsonify
from backend.services.shap_service import ShapService
from backend.utils.logger import logger

shap_bp = Blueprint('shap', __name__)

@shap_bp.route('/api/shap/<flow_id>', methods=['GET'])
def get_local_shap_explanation(flow_id):
    """
    Endpoint GET /api/shap/<flow_id>
    Fetches pre-calculated local feature parameters contributions.
    """
    try:
        result = ShapService.get_shap_for_flow(flow_id)
        if not result:
            return jsonify({"status": "error", "message": f"Explanation for flow {flow_id} not found."}), 404
        return jsonify({"status": "success", "data": result})
    except Exception as e:
        logger.error(f"Failed to fetch local explanations: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to compile explanations."}), 500

@shap_bp.route('/api/shap/importance', methods=['GET'])
def get_global_feature_importance():
    """
    Endpoint GET /api/shap/importance
    Returns global feature importance ratios for model visualization.
    """
    try:
        result = ShapService.get_global_importance()
        return jsonify({"status": "success", "data": result})
    except Exception as e:
        logger.error(f"Failed to load global importance weights: {str(e)}")
        return jsonify({"status": "error", "message": "Query failed."}), 500
