from backend.AI.rag_engine import RagEngine
from backend.AI.conversation_memory import ConversationMemory
from backend.services.prediction_service import PredictionService
from backend.utils.helpers import get_db_connection, row_to_dict
from backend.utils.logger import logger

class SecurityChatbot:
    @staticmethod
    def process_user_chat(session_id, user_message, flow_id=None, mode="professional"):
        """
        Processes user chat query: builds context, queries RAG, saves memory.
        """
        logger.info(f"Chatbot: Ingestion message for session {session_id} in Mode: {mode}")
        
        # 1. Fetch conversation history memory
        history = ConversationMemory.get_history(session_id, limit=6)
        
        # 2. Get active flow context if provided
        active_flow = None
        if flow_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM predictions WHERE flow_id = ?", (flow_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                active_flow = row_to_dict(row)
                
        # 3. Pull current dashboard stats context
        dashboard_stats = None
        try:
            dashboard_stats = PredictionService.get_aggregate_metrics()
        except Exception as e:
            logger.error(f"Chatbot: Failed to pull dashboard stats: {str(e)}")

        # 4. Save User Message in DB memory
        ConversationMemory.save_message(session_id, "user", user_message)
        
        # 5. Execute RAG query completion
        ai_response = RagEngine.answer_query(
            query=user_message,
            active_flow=active_flow,
            session_history=history,
            dashboard_stats=dashboard_stats,
            mode=mode
        )
        
        # 6. Save AI Response in DB memory
        ConversationMemory.save_message(session_id, "assistant", ai_response)
        
        return ai_response
