from flask import Blueprint, request, jsonify
from backend.services.prediction_service import PredictionService
from backend.utils.validation import validate_flow_payload
from backend.utils.logger import logger

prediction_bp = Blueprint('prediction', __name__)

@prediction_bp.route('/api/predict', methods=['POST'])
def run_prediction():
    """
    Endpoint POST /api/predict
    Evaluates individual network flow inputs.
    """
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No JSON payload provided."}), 400
        
    flow_id = data.get("flow_id", "FL-UNKNOWN")
    src_ip = data.get("src_ip", "0.0.0.0")
    dst_ip = data.get("dst_ip", "0.0.0.0")
    protocol = data.get("protocol", "TCP")
    port = data.get("port", 80)
    payload = data.get("payload", {})
    threshold = data.get("threshold", None)
    
    # Validate payload
    is_valid, msg = validate_flow_payload(payload)
    if not is_valid:
        return jsonify({"status": "error", "message": msg}), 422
        
    try:
        result = PredictionService.predict_and_store(
            flow_id, src_ip, dst_ip, protocol, port, payload, threshold
        )
        return jsonify({"status": "success", "data": result})
    except Exception as e:
        logger.error(f"Inference route failed: {str(e)}")
        return jsonify({"status": "error", "message": "Model execution failed."}), 500

@prediction_bp.route('/api/predict/batch', methods=['POST'])
def run_batch_prediction():
    """
    Endpoint POST /api/predict/batch
    Ingests array of logs, processes classification sequentially, writes to DB.
    """
    data = request.get_json()
    if not data or "flows" not in data:
        return jsonify({"status": "error", "message": "No flows lists provided."}), 400
        
    flows = data["flows"]
    threshold = data.get("threshold", None)
    
    results = []
    errors_count = 0
    
    for f in flows:
        try:
            res = PredictionService.predict_and_store(
                f["flow_id"],
                f["src_ip"],
                f["dst_ip"],
                f["protocol"],
                f["port"],
                f["payload"],
                threshold
            )
            results.append(res)
        except Exception as e:
            errors_count += 1
            logger.error(f"Batch index error on flow {f.get('flow_id')}: {str(e)}")
            
    return jsonify({
        "status": "success",
        "processed": len(results),
        "errors": errors_count,
        "data": results
    })

@prediction_bp.route('/api/predict/history', methods=['GET'])
def get_history():
    """
    Endpoint GET /api/predict/history
    Fetches prediction histories with standard search constraints.
    """
    query = request.args.get('q', None)
    pred_filter = request.args.get('filter', None)
    limit = request.args.get('limit', 100, type=int)
    
    results = PredictionService.get_prediction_history(query, pred_filter, limit)
    return jsonify({"status": "success", "data": results})

@prediction_bp.route('/api/predict/file', methods=['POST'])
def run_file_prediction():
    """
    Endpoint POST /api/predict/file
    Ingests file path, parses rows, runs predictions, and saves to DB.
    """
    data = request.get_json()
    if not data or "filepath" not in data:
        return jsonify({"status": "error", "message": "No filepath provided."}), 400
        
    filepath = data["filepath"]
    threshold = data.get("threshold", None)
    
    from backend.services.dataset_service import DatasetService
    
    # Load rows (limit to 30 rows for visual dashboard speed)
    flows = DatasetService.load_rows_for_detection(filepath, limit=30)
    if not flows:
        return jsonify({"status": "error", "message": "Failed to parse rows or dataset is empty."}), 422
        
    results = []
    errors_count = 0
    
    for f in flows:
        try:
            res = PredictionService.predict_and_store(
                f["flow_id"],
                f["src_ip"],
                f["dst_ip"],
                f["protocol"],
                f["port"],
                f["payload"],
                threshold
            )
            results.append(res)
        except Exception as e:
            errors_count += 1
            logger.error(f"File index prediction error on flow {f.get('flow_id')}: {str(e)}")
            
    return jsonify({
        "status": "success",
        "processed": len(results),
        "errors": errors_count,
        "message": f"Processed {len(results)} rows successfully."
    })

