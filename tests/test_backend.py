import os
import sys
import shutil
import unittest
import tempfile
import json
from datetime import datetime

# Resolve workspace path and define test temp directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

TEMP_TEST_DIR = os.path.join(BASE_DIR, 'tests', 'temp_test_files')
os.makedirs(TEMP_TEST_DIR, exist_ok=True)

# Override configuration parameters before importing Flask app
from backend.config import Config
Config.DATABASE_PATH = os.path.join(TEMP_TEST_DIR, 'test_database.db')
Config.UPLOAD_FOLDER = os.path.join(TEMP_TEST_DIR, 'uploads')
Config.REPORTS_FOLDER = os.path.join(TEMP_TEST_DIR, 'reports')
Config.DATASET_FOLDER = os.path.join(TEMP_TEST_DIR, 'dataset')
Config.init_app(None)

# Override vector store path
from backend.AI.vector_store import VectorStore
VectorStore._INDEX_PATH = os.path.join(TEMP_TEST_DIR, 'vector_store.json')
VectorStore.clear_index()

from backend.app import create_app
from backend.utils.validation import allowed_file, validate_csv_dataset, validate_flow_payload
from backend.utils.helpers import get_db_connection, init_db, row_to_dict
from backend.services.prediction_service import PredictionService
from backend.services.chat_service import ChatService
from backend.services.document_service import DocumentService
from backend.services.shap_service import ShapService
from backend.AI.llm_service import EmbeddedExpertSystem
from backend.AI.conversation_memory import ConversationMemory


class TestValidators(unittest.TestCase):
    def test_allowed_file(self):
        self.assertTrue(allowed_file("dataset.csv"))
        self.assertFalse(allowed_file("dataset.txt"))
        self.assertFalse(allowed_file("dataset"))

    def test_validate_flow_payload(self):
        valid_payload = {
            "Destination Port": 80,
            "Flow Duration": 1000,
            "Total Fwd Packets": 5,
            "Flow Packets/s": 10.0,
            "Fwd Packet Length Max": 1500
        }
        invalid_payload = {
            "Destination Port": 80,
            "Flow Duration": 1000
        }
        is_valid, msg = validate_flow_payload(valid_payload)
        self.assertTrue(is_valid)
        
        is_valid, msg = validate_flow_payload(invalid_payload)
        self.assertFalse(is_valid)
        self.assertIn("Missing required flow attributes", msg)

    def test_validate_csv_dataset(self):
        # Create a mock valid CSV
        csv_path = os.path.join(TEMP_TEST_DIR, "test_valid.csv")
        with open(csv_path, 'w') as f:
            f.write("col1,col2,col3,col4,col5\n1,2,3,4,5\n")
        
        is_valid, msg = validate_csv_dataset(csv_path)
        self.assertTrue(is_valid)
        
        # Create a mock invalid CSV
        csv_path_invalid = os.path.join(TEMP_TEST_DIR, "test_invalid.csv")
        with open(csv_path_invalid, 'w') as f:
            f.write("col1,col2\n1,2\n")
        
        is_valid, msg = validate_csv_dataset(csv_path_invalid)
        self.assertFalse(is_valid)
        self.assertIn("too few columns", msg)


class TestDatabaseAndHelpers(unittest.TestCase):
    def setUp(self):
        # Re-initialize DB
        if os.path.exists(Config.DATABASE_PATH):
            os.remove(Config.DATABASE_PATH)
        init_db()

    def test_init_db(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check tables existence
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn("predictions", tables)
        self.assertIn("metrics", tables)
        self.assertIn("model_info", tables)
        self.assertIn("conversations", tables)
        self.assertIn("uploaded_manuals", tables)
        
        # Verify seeded data
        cursor.execute("SELECT COUNT(*) FROM metrics")
        self.assertGreater(cursor.fetchone()[0], 0)
        
        cursor.execute("SELECT COUNT(*) FROM model_info")
        self.assertGreater(cursor.fetchone()[0], 0)
        
        conn.close()

    def test_row_to_dict(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM metrics LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        
        d = row_to_dict(row)
        self.assertIsInstance(d, dict)
        self.assertIn("threat_level", d)


class TestPredictionAndShap(unittest.TestCase):
    def setUp(self):
        if os.path.exists(Config.DATABASE_PATH):
            os.remove(Config.DATABASE_PATH)
        init_db()

    def test_predict_and_store(self):
        payload = {
            "Destination Port": 80,
            "Flow Duration": 120,
            "Total Fwd Packets": 2,
            "Total Length of Fwd Packets": 200,
            "Fwd Packet Length Max": 100,
            "Fwd Packet Length Mean": 50,
            "Bwd Packet Length Max": 100,
            "Bwd Packet Length Mean": 50,
            "Flow Bytes/s": 1000,
            "Flow Packets/s": 2,
            "SYN Flag Count": 0,
            "ACK Flag Count": 1
        }
        
        res = PredictionService.predict_and_store(
            flow_id="FL-TEST-101",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.10",
            protocol="TCP",
            port=80,
            payload=payload
        )
        
        self.assertEqual(res["flow_id"], "FL-TEST-101")
        self.assertIn("prediction", res)
        self.assertIn("confidence", res)
        self.assertIn("risk_level", res)
        self.assertIn("attack_type", res)
        self.assertIn("explanation", res)
        
        # Check SHAP service
        shap_res = ShapService.get_shap_for_flow("FL-TEST-101")
        self.assertIsNotNone(shap_res)
        self.assertEqual(shap_res["flow_id"], "FL-TEST-101")
        self.assertIsInstance(shap_res["shap_values"], list)

    def test_prediction_history_and_metrics(self):
        # Add basic test to prediction history
        metrics = PredictionService.get_aggregate_metrics()
        self.assertIn("total_packets", metrics)
        
        history = PredictionService.get_prediction_history()
        self.assertIsInstance(history, list)


class TestAIExpertSystemAndMemory(unittest.TestCase):
    def setUp(self):
        if os.path.exists(Config.DATABASE_PATH):
            os.remove(Config.DATABASE_PATH)
        init_db()

    def test_embedded_expert_system(self):
        # Test beginner mode
        resp_sql = EmbeddedExpertSystem.generate_response("explain what is sql injection")
        self.assertIn("SQL Injection", resp_sql)
        self.assertIn("Beginner Mode", resp_sql)
        
        # Test stats query
        resp_stats = EmbeddedExpertSystem.generate_response("what are the packets stats?", context={"dashboard_stats": {
            "total_packets": 500,
            "malicious_packets": 20,
            "normal_packets": 480,
            "accuracy": 99.0,
            "fpr": 0.5,
            "threat_level": "LOW"
        }})
        self.assertIn("SOC Dashboard Current Status", resp_stats)
        self.assertIn("500", resp_stats)
        
        # Test mitigation query
        resp_mitig = EmbeddedExpertSystem.generate_response("mitigate attacks threat from 192.168.1.1")
        self.assertIn("Incident Response", resp_mitig)
        self.assertIn("iptables", resp_mitig)

    def test_conversation_memory(self):
        sess_id = "test-session-999"
        ConversationMemory.save_message(sess_id, "user", "Hello Copilot")
        ConversationMemory.save_message(sess_id, "assistant", "Hello! How can I help you?")
        
        history = ConversationMemory.get_history(sess_id)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["role"], "user")
        self.assertEqual(history[1]["role"], "assistant")
        
        ConversationMemory.clear_history(sess_id)
        self.assertEqual(len(ConversationMemory.get_history(sess_id)), 0)


class TestFlaskAPI(unittest.TestCase):
    def setUp(self):
        if os.path.exists(Config.DATABASE_PATH):
            os.remove(Config.DATABASE_PATH)
        init_db()
        self.app = create_app()
        self.client = self.app.test_client()

    def test_health_check(self):
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["state"], "UP")

    def test_login(self):
        # Correct credentials
        resp = self.client.post('/login', json={"username": "admin", "password": "password123"})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        
        # Incorrect credentials
        resp_err = self.client.post('/login', json={"username": "admin", "password": "wrongpassword"})
        self.assertEqual(resp_err.status_code, 401)

    def test_dashboard_metrics_and_recent_attacks(self):
        resp = self.client.get('/api/dashboard')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        self.assertIn("total_packets", data["data"])

        resp_attacks = self.client.get('/api/recent-attacks')
        self.assertEqual(resp_attacks.status_code, 200)
        data_attacks = json.loads(resp_attacks.data)
        self.assertEqual(data_attacks["status"], "success")

    def test_prediction_endpoints(self):
        # Predict single flow log
        payload = {
            "flow_id": "FL-ROUTE-TEST",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "protocol": "TCP",
            "port": 443,
            "payload": {
                "Destination Port": 443,
                "Flow Duration": 50,
                "Total Fwd Packets": 3,
                "Flow Packets/s": 60.0,
                "Fwd Packet Length Max": 200
            }
        }
        resp = self.client.post('/api/predict', json=payload)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["flow_id"], "FL-ROUTE-TEST")

        # Predict batch
        batch_payload = {
            "flows": [payload]
        }
        resp_batch = self.client.post('/api/predict/batch', json=batch_payload)
        self.assertEqual(resp_batch.status_code, 200)
        data_batch = json.loads(resp_batch.data)
        self.assertEqual(data_batch["status"], "success")
        self.assertEqual(data_batch["processed"], 1)

    def test_chat_endpoints(self):
        chat_payload = {
            "session_id": "api-session",
            "message": "mitigate DDOS from 192.168.1.10",
            "ai_mode": "professional"
        }
        # Post chat
        resp = self.client.post('/api/chat', json=chat_payload)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        self.assertIn("response", data["data"])

        # Get history
        resp_hist = self.client.get('/api/chat/history?session_id=api-session')
        self.assertEqual(resp_hist.status_code, 200)
        data_hist = json.loads(resp_hist.data)
        self.assertEqual(data_hist["status"], "success")
        self.assertEqual(len(data_hist["data"]), 2) # User + AI

        # Clear history
        resp_clear = self.client.post('/api/chat/clear', json={"session_id": "api-session"})
        self.assertEqual(resp_clear.status_code, 200)

    def test_reports_api(self):
        # We need at least one prediction in the DB to construct a report
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO predictions (flow_id, timestamp, src_ip, dst_ip, protocol, port, prediction, confidence, risk_level, attack_type, explanation, shap_values) VALUES ('FL-REP-1', '2026-07-30 12:00:00', '192.168.1.1', '10.0.0.1', 'TCP', 80, 'Attack', 98.5, 'High', 'PortScan', 'SHAP expl', '[]')")
        conn.commit()
        conn.close()

        # Download PDF report
        resp_pdf = self.client.get('/api/reports/download?format=pdf')
        self.assertEqual(resp_pdf.status_code, 200)
        self.assertEqual(resp_pdf.mimetype, 'application/pdf')

        # Download CSV report
        resp_csv = self.client.get('/api/reports/download?format=csv')
        self.assertEqual(resp_csv.status_code, 200)
        self.assertEqual(resp_csv.mimetype, 'text/csv')

        # Download AI Incident PDF Report
        resp_ai = self.client.get('/api/reports/ai?flow_id=FL-REP-1')
        self.assertEqual(resp_ai.status_code, 200)
        self.assertEqual(resp_ai.mimetype, 'application/pdf')

    def test_settings_api(self):
        # Test GET settings
        resp = self.client.get('/api/settings')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        self.assertIn("gemini_api_key_set", data["data"])
        self.assertIn("groq_api_key_set", data["data"])
        
        # Test POST settings
        resp_post = self.client.post('/api/settings', json={
            "gemini_api_key": "test_gemini_key",
            "groq_api_key": "test_groq_key"
        })
        self.assertEqual(resp_post.status_code, 200)
        data_post = json.loads(resp_post.data)
        self.assertEqual(data_post["status"], "success")
        
        # Verify it updated env
        import os
        self.assertEqual(os.environ.get("GEMINI_API_KEY"), "test_gemini_key")
        self.assertEqual(os.environ.get("GROQ_API_KEY"), "test_groq_key")


if __name__ == '__main__':
    unittest.main()
