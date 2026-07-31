import os
import pandas as pd
from werkzeug.utils import secure_filename
from backend.config import Config
from backend.utils.validation import allowed_file, validate_csv_dataset
from backend.utils.logger import logger

class DatasetService:
    @staticmethod
    def save_and_validate_upload(file):
        """
        Saves uploaded file and runs schema and size validation checks.
        """
        if not file or file.filename == '':
            return False, "No file selected."
            
        if not allowed_file(file.filename):
            return False, "File type rejected. Only CSV dataset files are allowed."
            
        filename = secure_filename(file.filename)
        filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
        
        # Save file to disk
        file.save(filepath)
        logger.info(f"File uploaded to {filepath}")
        
        # Validate CSV contents
        is_valid, msg = validate_csv_dataset(filepath)
        if not is_valid:
            # Delete file if invalid
            if os.path.exists(filepath):
                os.remove(filepath)
            logger.warning(f"Uploaded dataset validation failed: {msg}")
            return False, msg
            
        # Extract metadata
        try:
            df = pd.read_csv(filepath)
            metadata = {
                "dataset_name": filename,
                "size": f"{os.path.getsize(filepath) / 1024:.2f} KB",
                "rows": int(len(df)),
                "columns": int(len(df.columns)),
                "filepath": filepath
            }
            logger.info(f"Dataset successfully validated: {metadata}")
            return True, metadata
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            return False, f"Failed to parse CSV values: {str(e)}"

    @staticmethod
    def load_rows_for_detection(filepath, limit=100):
        """
        Parses uploaded CSV and returns rows as dictionaries ready for model prediction.
        """
        try:
            df = pd.read_csv(filepath, nrows=limit)
            # Remove whitespace from column names
            df.columns = df.columns.str.strip()
            df = df.dropna()
            
            # Map columns to target keys or pad missing with defaults
            rows = df.to_dict(orient='records')
            
            # Generate realistic IP/Protocol/Time tags since raw CSV usually only has numerical headers
            processed_rows = []
            for idx, r in enumerate(rows):
                # Fake IPs for visualization
                src_ip = f"192.168.1.{random_ip_end(idx, 10)}"
                dst_ip = f"10.0.0.{random_ip_end(idx, 120)}"
                proto = "TCP" if r.get("SYN Flag Count", 0) > 0 or r.get("ACK Flag Count", 0) > 0 else "UDP"
                port = int(r.get("Destination Port", 80))
                
                processed_rows.append({
                    "flow_id": f"FL-{1000 + idx}",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "port": port,
                    "payload": r
                })
            return processed_rows
        except Exception as e:
            logger.error(f"Failed to load dataset rows: {str(e)}")
            return []

def random_ip_end(idx, offset):
    return (idx * 7 + offset) % 254 + 1
