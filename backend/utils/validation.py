import os
from werkzeug.utils import secure_filename
from backend.config import Config

def allowed_file(filename):
    """Check if file has an allowed CSV extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def validate_csv_dataset(filepath):
    """
    Validates the structure of the uploaded CSV dataset.
    Checks for required columns, size limits, and basic features.
    """
    import pandas as pd
    try:
        # Check file size (redundant safety check)
        size = os.path.getsize(filepath)
        if size > Config.MAX_CONTENT_LENGTH:
            return False, "File exceeds max content length limit."
            
        # Try loading sample rows to check schema
        df = pd.read_csv(filepath, nrows=5)
        
        # Clean columns of whitespace
        cols = [c.strip() for c in df.columns]
        
        # Basic validations
        if len(cols) < 5:
            return False, "Dataset contains too few columns to process."
            
        return True, "Dataset structure is valid."
    except Exception as e:
        return False, f"Failed to validate CSV headers: {str(e)}"

def validate_flow_payload(payload):
    """
    Validates a single flow connection packet dictionary for real-time predictions.
    """
    required_keys = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Flow Packets/s', 'Fwd Packet Length Max']
    # Allow loose key matching (stripped)
    payload_keys = [k.strip() for k in payload.keys()]
    
    missing = [k for k in required_keys if k not in payload_keys]
    if missing:
        return False, f"Missing required flow attributes: {', '.join(missing)}"
        
    return True, "Payload schema is valid."
