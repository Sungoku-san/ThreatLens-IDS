import sys
import os

# Ensure the root project directory is first in sys.path
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Ensure matplotlib uses writable /tmp directory in serverless environment
os.environ.setdefault('MPLCONFIGDIR', '/tmp')

# Top-level import and assignments for Vercel WSGI entrypoint detection
from backend.app import app

application = app
handler = app
