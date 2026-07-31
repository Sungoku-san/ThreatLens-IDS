from flask import Blueprint, request, jsonify
from backend.services.document_service import DocumentService
from backend.utils.logger import logger

document_bp = Blueprint('document', __name__)

@document_bp.route('/api/documents/upload', methods=['POST'])
def upload_manual_document():
    """
    Endpoint POST /api/documents/upload
    Ingests PDF/TXT guidelines, chunks, and creates vectors indexes.
    """
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file parameter part."}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file."}), 400
        
    success, result = DocumentService.process_and_index_manual(file)
    if not success:
        return jsonify({"status": "error", "message": result}), 422
        
    return jsonify({
        "status": "success",
        "message": "Manual document successfully parsed and indexed in vector database.",
        "data": result
    })

@document_bp.route('/api/documents/list', methods=['GET'])
def get_documents_list():
    """
    Endpoint GET /api/documents/list
    Returns ingested manuals files list.
    """
    try:
        manuals = DocumentService.get_manuals_list()
        return jsonify({"status": "success", "data": manuals})
    except Exception as e:
        logger.error(f"Failed to fetch document lists: {str(e)}")
        return jsonify({"status": "error", "message": "Database query failed."}), 500

@document_bp.route('/api/documents/search', methods=['GET'])
def search_manual_documents():
    """
    Endpoint GET /api/documents/search
    Queries manual contents using vector embeddings.
    """
    query = request.args.get('q', '')
    if not query:
        return jsonify({"status": "error", "message": "No query provided."}), 400
        
    from backend.AI.manual_search import ManualSearch
    
    try:
        matches = ManualSearch.search_manuals(query, top_k=3)
        # Format output
        results = []
        for m in matches:
            results.append({
                "text": m["text"],
                "similarity": m["similarity"],
                "source": m["metadata"].get("source", "Unknown Manual")
            })
        return jsonify({"status": "success", "data": results})
    except Exception as e:
        logger.error(f"Documents search failed: {str(e)}")
        return jsonify({"status": "error", "message": "Search engine failed."}), 500
