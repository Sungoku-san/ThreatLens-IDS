import os
import sqlite3
import json
from datetime import datetime
from backend.config import Config

def get_db_connection():
    """Context connection to the SQLite database."""
    try:
        os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    except OSError:
        pass
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite database tables if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Predictions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_level TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            explanation TEXT NOT NULL,
            shap_values TEXT NOT NULL
        )
    ''')
    
    # 2. Daily Metrics Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            total_packets INTEGER NOT NULL,
            total_attacks INTEGER NOT NULL,
            normal_packets INTEGER NOT NULL,
            malicious_packets INTEGER NOT NULL,
            accuracy REAL NOT NULL,
            fpr REAL NOT NULL,
            threat_level TEXT NOT NULL
        )
    ''')
    
    # 3. Model Info Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT NOT NULL,
            accuracy REAL NOT NULL,
            precision REAL NOT NULL,
            recall REAL NOT NULL,
            f1_score REAL NOT NULL,
            roc_auc REAL NOT NULL,
            trained_at TEXT NOT NULL,
            active INTEGER NOT NULL
        )
    ''')
    
    # 4. Conversations Table (AI memory)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            role TEXT NOT NULL,
            message TEXT NOT NULL
        )
    ''')
    
    # 5. Uploaded Manuals Table (RAG documents library)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uploaded_manuals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL UNIQUE,
            filepath TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            chunks_count INTEGER NOT NULL
        )
    ''')

    # 6. Incidents Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL UNIQUE,
            flow_id TEXT,
            detection_time TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            confidence REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW',
            assigned_analyst TEXT DEFAULT 'SOC Analyst 1',
            recommended_actions TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')

    # 7. Audit Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            user TEXT NOT NULL,
            details TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'SUCCESS'
        )
    ''')

    # 8. Model Evaluations Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_evaluations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT NOT NULL,
            evaluation_time TEXT NOT NULL,
            dataset_name TEXT NOT NULL,
            total_samples INTEGER NOT NULL,
            accuracy REAL NOT NULL,
            precision REAL NOT NULL,
            recall REAL NOT NULL,
            f1_score REAL NOT NULL,
            roc_auc REAL NOT NULL,
            correct_predictions INTEGER NOT NULL,
            incorrect_predictions INTEGER NOT NULL,
            classes_json TEXT NOT NULL,
            confusion_matrix_json TEXT NOT NULL,
            classification_report_json TEXT NOT NULL,
            comparison_json TEXT NOT NULL,
            dataset_analysis_json TEXT NOT NULL,
            quality_checks_json TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    ''')

    # Schema Migrations: Safely check for new columns in predictions
    try:
        cursor.execute("PRAGMA table_info(predictions)")
        pred_cols = [col[1] for col in cursor.fetchall()]
        if 'risk_score' not in pred_cols:
            cursor.execute("ALTER TABLE predictions ADD COLUMN risk_score INTEGER DEFAULT 0")
        if 'anomaly_score' not in pred_cols:
            cursor.execute("ALTER TABLE predictions ADD COLUMN anomaly_score REAL DEFAULT 0.0")
        if 'is_anomaly' not in pred_cols:
            cursor.execute("ALTER TABLE predictions ADD COLUMN is_anomaly INTEGER DEFAULT 0")
    except Exception:
        pass

    # Check if we need to seed initial mock statistics
    cursor.execute("SELECT COUNT(*) FROM metrics")
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO metrics (timestamp, total_packets, total_attacks, normal_packets, malicious_packets, accuracy, fpr, threat_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 284100, 2284, 281816, 2284, 99.42, 0.11, "MODERATE"))
        
    # Check if we need to seed model info
    cursor.execute("SELECT COUNT(*) FROM model_info")
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO model_info (model_name, accuracy, precision, recall, f1_score, roc_auc, trained_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ("Random Forest Ingestion Classifier", 0.9942, 0.9921, 0.9930, 0.9925, 0.9984, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 1))

    # Check if we need to seed initial incidents
    cursor.execute("SELECT COUNT(*) FROM incidents")
    if cursor.fetchone()[0] == 0:
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        seed_incidents = [
            ("INC-2026-001", "FL-7294", now_str, "DDoS Ingress Exploit", "CRITICAL", 94, 99.42, "192.168.1.105", "10.0.0.1", 80, "TCP", "NEW", "Lead Analyst", "Apply perimeter rate limit and drop SYN packets at edge firewall"),
            ("INC-2026-002", "FL-8102", now_str, "Port Scanner Reconnaissance", "HIGH", 78, 93.10, "172.16.0.45", "10.0.0.12", 443, "TCP", "INVESTIGATING", "SOC Analyst 2", "Block source IP in IPTables and inspect access log headers"),
            ("INC-2026-003", "FL-9041", now_str, "SSH Brute-Force Authentication", "HIGH", 82, 95.80, "198.51.100.24", "10.0.0.22", 22, "TCP", "CONTAINED", "Security Admin", "Isolate SSH daemon, enforce key-only authentication and fail2ban rules"),
            ("INC-2026-004", "FL-9520", now_str, "Anomalous Traffic Outlier", "MEDIUM", 55, 72.40, "203.0.113.88", "10.0.0.80", 8080, "TCP", "RESOLVED", "SOC Analyst 1", "Verified anomalous telemetry spike from scheduled load test; marked resolved")
        ]
        for inc in seed_incidents:
            cursor.execute('''
                INSERT INTO incidents (
                    incident_id, flow_id, detection_time, attack_type, severity,
                    risk_score, confidence, src_ip, dst_ip, port, protocol,
                    status, assigned_analyst, recommended_actions, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (inc[0], inc[1], inc[2], inc[3], inc[4], inc[5], inc[6], inc[7], inc[8], inc[9], inc[10], inc[11], inc[12], inc[13], now_str, now_str))

    # Check if we need to seed initial audit logs
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    if cursor.fetchone()[0] == 0:
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        seed_logs = [
            (now_str, "SYSTEM_INITIALIZE", "SYSTEM", "ThreatLens SOC Core initialized and database verified", "SUCCESS"),
            (now_str, "MODEL_LOAD", "ML_ENGINE", "Random Forest classifier mounted with 12 features", "SUCCESS"),
            (now_str, "ANOMALY_ENGINE_INIT", "ANOMALY_ENGINE", "Isolation Forest unsupervised engine calibrated", "SUCCESS"),
            (now_str, "INCIDENT_CREATED", "RULE_ENGINE", "Incident INC-2026-001 created automatically from high-risk DDoS detection", "SUCCESS")
        ]
        for l in seed_logs:
            cursor.execute('''
                INSERT INTO audit_logs (timestamp, action, user, details, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (l[0], l[1], l[2], l[3], l[4]))
        
    conn.commit()
    conn.close()

def row_to_dict(row):
    """Converts a sqlite3.Row object to a standard dict."""
    d = dict(row)
    # Parse JSON properties automatically
    json_keys = [
        'shap_values', 'classes_json', 'confusion_matrix_json', 
        'classification_report_json', 'comparison_json', 
        'dataset_analysis_json', 'quality_checks_json'
    ]
    for key in json_keys:
        if key in d and d[key] is not None and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except Exception:
                pass
    return d

def update_env_keys(gemini_key=None, openai_key=None, groq_key=None):
    """
    Updates GEMINI_API_KEY, OPENAI_API_KEY, and GROQ_API_KEY in .env files and os.environ.
    """
    import os
    
    # 1. Update os.environ
    if gemini_key is not None:
        os.environ["GEMINI_API_KEY"] = gemini_key
    if openai_key is not None:
        os.environ["OPENAI_API_KEY"] = openai_key
    if groq_key is not None:
        os.environ["GROQ_API_KEY"] = groq_key

    # 2. Write to .env files
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root_dir = os.path.dirname(base_dir)
    
    env_paths = [
        os.path.join(base_dir, '.env'),
        os.path.join(root_dir, '.env')
    ]
    
    for path in env_paths:
        lines = []
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        
        # Parse existing lines and update or insert
        updated_gemini = False
        updated_openai = False
        updated_groq = False
        new_lines = []
        
        for line in lines:
            line_strip = line.strip()
            if line_strip.startswith("GEMINI_API_KEY="):
                if gemini_key is not None:
                    new_lines.append(f"GEMINI_API_KEY={gemini_key}\n")
                    updated_gemini = True
                else:
                    new_lines.append(line)
            elif line_strip.startswith("OPENAI_API_KEY="):
                if openai_key is not None:
                    new_lines.append(f"OPENAI_API_KEY={openai_key}\n")
                    updated_openai = True
                else:
                    new_lines.append(line)
            elif line_strip.startswith("GROQ_API_KEY="):
                if groq_key is not None:
                    new_lines.append(f"GROQ_API_KEY={groq_key}\n")
                    updated_groq = True
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
                
        if not updated_gemini and gemini_key is not None:
            new_lines.append(f"GEMINI_API_KEY={gemini_key}\n")
        if not updated_openai and openai_key is not None:
            new_lines.append(f"OPENAI_API_KEY={openai_key}\n")
        if not updated_groq and groq_key is not None:
            new_lines.append(f"GROQ_API_KEY={groq_key}\n")
            
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
        except OSError:
            pass

