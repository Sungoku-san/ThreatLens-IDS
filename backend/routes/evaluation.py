from flask import Blueprint, request, jsonify
from backend.services.evaluation_service import EvaluationService
from backend.models.shap_explainer import get_global_feature_importance
from backend.utils.logger import logger

evaluation_bp = Blueprint('evaluation', __name__)

@evaluation_bp.route('/api/model/evaluation', methods=['GET'])
def get_model_evaluation():
    """
    Endpoint GET /api/model/evaluation
    Returns genuine statistical evaluation metrics over the test dataset.
    """
    force = request.args.get('refresh', 'false').lower() == 'true'
    try:
        results = EvaluationService.run_evaluation(force_refresh=force)
        return jsonify({
            "status": "success",
            "data": results
        })
    except Exception as e:
        logger.error(f"Model evaluation failed: {e}")
        return jsonify({
            "status": "error",
            "message": f"Unable to evaluate model. Reason: {str(e)}"
        }), 500

@evaluation_bp.route('/api/model/evaluate', methods=['POST'])
def trigger_evaluation():
    """
    Endpoint POST /api/model/evaluate
    Forces a fresh run of the model evaluation pipeline on the test dataset.
    """
    data = request.get_json() or {}
    dataset_path = data.get("dataset_path", None)
    try:
        results = EvaluationService.run_evaluation(dataset_path=dataset_path, force_refresh=True)
        return jsonify({
            "status": "success",
            "message": "Model evaluation completed successfully.",
            "data": results
        })
    except Exception as e:
        logger.error(f"Evaluation trigger failed: {e}")
        return jsonify({
            "status": "error",
            "message": f"Unable to evaluate model. Reason: {str(e)}"
        }), 500

@evaluation_bp.route('/api/model/features', methods=['GET'])
def get_feature_importances():
    """
    Endpoint GET /api/model/features
    Returns global feature importance ranking.
    """
    try:
        ranked = get_global_feature_importance()
        return jsonify({
            "status": "success",
            "data": ranked
        })
    except Exception as e:
        logger.error(f"Failed to fetch feature importances: {e}")
        return jsonify({
            "status": "error",
            "message": "Failed to calculate feature importances."
        }), 500
