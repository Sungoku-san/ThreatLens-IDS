import sys
import os

# Ensure the root project directory is first in sys.path
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.app import app

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
