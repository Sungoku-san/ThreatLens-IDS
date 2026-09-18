import sys
import os

# Ensure the root project directory is first in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    from backend.app import app
except Exception as e:
    import traceback
    _startup_error = traceback.format_exc()
    from flask import Flask, Response
    app = Flask(__name__)
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def _error_fallback(path):
        return Response(
            f"<h1>ThreatLens IDS Startup Error</h1><pre style='color:red;'>{_startup_error}</pre>",
            mimetype="text/html",
            status=500
        )
