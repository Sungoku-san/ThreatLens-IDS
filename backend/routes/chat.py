from flask import Blueprint, request, jsonify
from backend.services.chat_service import ChatService
from backend.utils.logger import logger

chat_bp = Blueprint('chat', __name__)

@chat_bp.route('/api/chat', methods=['POST'])
def handle_chat_message():
    """
    Endpoint POST /api/chat
    Submits user message and returns Copilot security analyst feedback.
    """
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"status": "error", "message": "No query message provided."}), 400
        
    session_id = data.get("session_id", "default_session")
    message = data.get("message")
    flow_id = data.get("flow_id", None)
    mode = data.get("mode", data.get("ai_mode", "professional"))
    
    try:
        response = ChatService.send_chat_message(session_id, message, flow_id, mode)
        return jsonify({"status": "success", "data": {"response": response}})
    except Exception as e:
        logger.error(f"Chat API route error: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to compile AI response."}), 500

@chat_bp.route('/api/chat/history', methods=['GET'])
def get_chat_history():
    """
    Endpoint GET /api/chat/history
    Retrieves previous logs in session.
    """
    session_id = request.args.get('session_id', 'default_session')
    try:
        history = ChatService.get_session_history(session_id)
        return jsonify({"status": "success", "data": history})
    except Exception as e:
        logger.error(f"History query error: {str(e)}")
        return jsonify({"status": "error", "message": "Query failed."}), 500

@chat_bp.route('/api/chat/clear', methods=['POST'])
def clear_chat_history():
    """
    Endpoint POST /api/chat/clear
    Wipes conversation caches.
    """
    data = request.get_json() or {}
    session_id = data.get("session_id", "default_session")
    try:
        ChatService.reset_chat_session(session_id)
        return jsonify({"status": "success", "message": "Session history wiped."})
    except Exception as e:
        logger.error(f"Clear history error: {str(e)}")
        return jsonify({"status": "error", "message": "Wipe failed."}), 500
