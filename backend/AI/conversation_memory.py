from datetime import datetime
from backend.utils.helpers import get_db_connection, row_to_dict
from backend.utils.logger import logger

class ConversationMemory:
    @staticmethod
    def save_message(session_id, role, message):
        """Saves a single conversation chat log (user/assistant) in SQLite."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                INSERT INTO conversations (session_id, timestamp, role, message)
                VALUES (?, ?, ?, ?)
            ''', (session_id, timestamp, role, message))
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to save conversation message: {str(e)}")
        finally:
            conn.close()

    @staticmethod
    def get_history(session_id, limit=30):
        """Retrieves messages history sorted by timestamp."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                SELECT role, message, timestamp 
                FROM conversations 
                WHERE session_id = ? 
                ORDER BY id ASC LIMIT ?
            ''', (session_id, limit))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to fetch conversation history: {str(e)}")
            return []
        finally:
            conn.close()

    @staticmethod
    def clear_history(session_id):
        """Clears logs history for a session."""
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM conversations WHERE session_id = ?", (session_id,))
            conn.commit()
            logger.info(f"Conversation history cleared for session {session_id}")
        except Exception as e:
            logger.error(f"Failed to clear conversation history: {str(e)}")
        finally:
            conn.close()
