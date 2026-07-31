from backend.AI.chatbot import SecurityChatbot
from backend.AI.conversation_memory import ConversationMemory

class ChatService:
    @staticmethod
    def send_chat_message(session_id, message, flow_id=None, mode="professional"):
        """Processes message and returns Copilot analyst responses."""
        return SecurityChatbot.process_user_chat(session_id, message, flow_id, mode)
        
    @staticmethod
    def get_session_history(session_id):
        """Retrieves session messages history logs."""
        return ConversationMemory.get_history(session_id)
        
    @staticmethod
    def reset_chat_session(session_id):
        """Clears memory history for the chat session."""
        ConversationMemory.clear_history(session_id)
        return True
