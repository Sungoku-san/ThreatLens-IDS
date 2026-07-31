import os
import sqlite3
import json
from datetime import datetime
from backend.config import Config

def get_db_connection():
    """Context connection to the SQLite database."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
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
        
    conn.commit()
    conn.close()

def row_to_dict(row):
    """Converts a sqlite3.Row object to a standard dict."""
    d = dict(row)
    # Parse JSON properties automatically
    if 'shap_values' in d:
        try:
            d['shap_values'] = json.loads(d['shap_values'])
        except:
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
            
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

