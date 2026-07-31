from flask import Blueprint, request, jsonify
from backend.AI.manual_search import ManualSearch
from backend.services.document_service import DocumentService
from backend.utils.logger import logger

manual_bp = Blueprint('manual', __name__)

@manual_bp.route('/api/manual', methods=['GET'])
def search_manual():
    """
    Endpoint GET /api/manual?q=search_query
    Runs a semantic search over uploaded manuals.
    """
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({"status": "error", "message": "Missing search query parameter 'q'."}), 400
        
    try:
        results = ManualSearch.search_manuals(q)
        logger.info(f"ManualSearch API: Found {len(results)} matches for query '{q}'")
        return jsonify({"status": "success", "data": results})
    except Exception as e:
        logger.error(f"Manual search route error: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to perform semantic search."}), 500

@manual_bp.route('/api/manual/global', methods=['GET'])
def global_search_endpoint():
    """
    Endpoint GET /api/manual/global?q=search_query
    Executes global smart search across manuals, knowledge base, and threat databases.
    """
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({"status": "error", "message": "Missing search query parameter 'q'."}), 400
        
    try:
        results = ManualSearch.global_search(q)
        return jsonify({"status": "success", "data": results})
    except Exception as e:
        logger.error(f"Global smart search route error: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to perform global search."}), 500
