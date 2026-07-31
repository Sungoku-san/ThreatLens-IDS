import os
import logging
from logging.handlers import RotatingFileHandler

def setup_logger(name="cyber_ids"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
        
    logger.setLevel(logging.INFO)
    
    # Create logs directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logs_dir = os.path.join(base_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    # Formatter
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s (%(process)d): %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File Handler (Rotate at 5MB, keep 5 backups)
    log_file = os.path.join(logs_dir, 'app.log')
    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Stream Handler (console)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.INFO)
    
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    
    return logger

logger = setup_logger()
