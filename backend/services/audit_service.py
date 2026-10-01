from datetime import datetime
from backend.utils.helpers import get_db_connection, row_to_dict
from backend.utils.logger import logger

class AuditService:
    """
    Security Audit Logger for ThreatLens SOC Platform.
    Tracks sensitive user and system events without logging credentials or tokens.
    """

    @staticmethod
    def log(action, user="SOC_Analyst", details="", status="SUCCESS"):
        from backend.utils.helpers import init_db
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                INSERT INTO audit_logs (timestamp, action, user, details, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, str(action), str(user), str(details), str(status)))
            conn.commit()
            conn.close()
        except Exception:
            try:
                init_db()
                conn = get_db_connection()
                cursor = conn.cursor()
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute('''
                    INSERT INTO audit_logs (timestamp, action, user, details, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (timestamp, str(action), str(user), str(details), str(status)))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"AuditService failed to log event: {e}")

    @staticmethod
    def get_logs(limit=100):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [row_to_dict(r) for r in rows]
        except Exception as e:
            logger.error(f"AuditService failed to fetch logs: {e}")
            return []
