from flask import Blueprint, request, jsonify
from backend.AI.knowledge_base import KnowledgeBase
from backend.utils.logger import logger

knowledge_bp = Blueprint('knowledge', __name__)

@knowledge_bp.route('/api/knowledge', methods=['GET'])
def get_knowledge_articles():
    """
    Endpoint GET /api/knowledge
    Searches the cybersecurity knowledge base or returns all articles.
    """
    q = request.args.get('q', '').strip()
    try:
        if q:
            results = KnowledgeBase.search(q)
            logger.info(f"KnowledgeBase API: Found {len(results)} matches for query '{q}'")
            return jsonify({"status": "success", "data": results})
        else:
            # Return all articles grouped
            all_articles = list(KnowledgeBase.ARTICLES.values())
            return jsonify({"status": "success", "data": all_articles})
    except Exception as e:
        logger.error(f"Knowledge Base route error: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to query knowledge base."}), 500
