import random
from datetime import datetime
from backend.utils.helpers import get_db_connection, row_to_dict
from backend.services.audit_service import AuditService
from backend.utils.logger import logger

class IncidentService:
    """
    Incident Management Engine for ThreatLens SOC Platform.
    Tracks security incidents, operational workflows, and analyst triage status.
    """

    VALID_STATUSES = ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE POSITIVE"]
    VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    @staticmethod
    def generate_incident_id():
        date_str = datetime.now().strftime('%Y%m%d')
        rand_suffix = random.randint(100, 999)
        return f"INC-{date_str}-{rand_suffix}"

    @staticmethod
    def create_incident(flow_id, attack_type, severity, risk_score, confidence,
                        src_ip, dst_ip, port=80, protocol="TCP",
                        assigned_analyst="SOC Analyst 1", recommended_actions=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        incident_id = IncidentService.generate_incident_id()

        # Check if an open incident already exists for this flow_id
        if flow_id:
            cursor.execute("SELECT * FROM incidents WHERE flow_id = ? AND status != 'RESOLVED'", (flow_id,))
            existing = cursor.fetchone()
            if existing:
                conn.close()
                return row_to_dict(existing)

        actions_str = recommended_actions or f"Quarantine source {src_ip} and inspect firewall logs for port {port}."

        try:
            cursor.execute('''
                INSERT INTO incidents (
                    incident_id, flow_id, detection_time, attack_type, severity,
                    risk_score, confidence, src_ip, dst_ip, port, protocol,
                    status, assigned_analyst, recommended_actions, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident_id, flow_id, now_str, attack_type, severity.upper(),
                int(risk_score), float(confidence), src_ip, dst_ip, int(port), protocol,
                "NEW", assigned_analyst, actions_str, now_str, now_str
            ))
            conn.commit()

            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            created = cursor.fetchone()
            conn.close()

            AuditService.log("INCIDENT_CREATED", assigned_analyst, f"Created incident {incident_id} for {attack_type} ({severity})")
            return row_to_dict(created)
        except Exception as e:
            conn.close()
            logger.error(f"Failed to create incident: {e}")
            raise e

    @staticmethod
    def get_incidents(status=None, severity=None, search=None, limit=100):
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = "SELECT * FROM incidents"
        conditions = []
        params = []

        if status and status.upper() != 'ALL':
            conditions.append("status = ?")
            params.append(status.upper())

        if severity and severity.upper() != 'ALL':
            conditions.append("severity = ?")
            params.append(severity.upper())

        if search:
            conditions.append("(incident_id LIKE ? OR flow_id LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR attack_type LIKE ?)")
            q = f"%{search}%"
            params.extend([q, q, q, q, q])

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        conn.close()

        return [row_to_dict(r) for r in rows]

    @staticmethod
    def get_incident_by_id(incident_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        conn.close()
        return row_to_dict(row) if row else None

    @staticmethod
    def update_incident_status(incident_id, status, assigned_analyst=None, notes=None):
        if status.upper() not in IncidentService.VALID_STATUSES:
            raise ValueError(f"Invalid incident status: {status}")

        conn = get_db_connection()
        cursor = conn.cursor()
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        update_fields = ["status = ?", "updated_at = ?"]
        params = [status.upper(), now_str]

        if assigned_analyst:
            update_fields.append("assigned_analyst = ?")
            params.append(assigned_analyst)

        if notes:
            update_fields.append("recommended_actions = recommended_actions || ' | Notes: ' || ?")
            params.append(notes)

        params.append(incident_id)

        sql = f"UPDATE incidents SET {', '.join(update_fields)} WHERE incident_id = ?"
        cursor.execute(sql, tuple(params))
        conn.commit()

        cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        updated = cursor.fetchone()
        conn.close()

        if updated:
            AuditService.log("INCIDENT_STATUS_CHANGE", assigned_analyst or "SOC Analyst", f"Updated {incident_id} status to {status.upper()}")
            return row_to_dict(updated)
        return None

    @staticmethod
    def get_statistics():
        conn = get_db_connection()
        cursor = conn.cursor()

        # Status counts
        cursor.execute("SELECT status, COUNT(*) as cnt FROM incidents GROUP BY status")
        status_counts = {r['status']: r['cnt'] for r in cursor.fetchall()}

        # Severity counts
        cursor.execute("SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity")
        severity_counts = {r['severity']: r['cnt'] for r in cursor.fetchall()}

        # Total count
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total = cursor.fetchone()[0]

        # Active load (not resolved or false positive)
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('NEW', 'INVESTIGATING', 'CONTAINED')")
        active_load = cursor.fetchone()[0]

        conn.close()

        return {
            "total_incidents": total,
            "active_load": active_load,
            "by_status": {
                "NEW": status_counts.get("NEW", 0),
                "INVESTIGATING": status_counts.get("INVESTIGATING", 0),
                "CONTAINED": status_counts.get("CONTAINED", 0),
                "RESOLVED": status_counts.get("RESOLVED", 0),
                "FALSE_POSITIVE": status_counts.get("FALSE POSITIVE", 0)
            },
            "by_severity": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
                "LOW": severity_counts.get("LOW", 0)
            }
        }
