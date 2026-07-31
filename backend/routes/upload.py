from flask import Blueprint, request, jsonify
from backend.services.dataset_service import DatasetService
from backend.utils.logger import logger

upload_bp = Blueprint('upload', __name__)

@upload_bp.route('/api/upload', methods=['POST'])
def upload_dataset():
    """
    Endpoint POST /api/upload
    Receives CSV dataset file, saves, and validates metadata schema.
    """
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file parameter part in the request."}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file to upload."}), 400
        
    success, result = DatasetService.save_and_validate_upload(file)
    
    if not success:
        return jsonify({"status": "error", "message": result}), 422
        
    return jsonify({
        "status": "success",
        "message": "Dataset successfully uploaded and validated.",
        "data": result
    })
