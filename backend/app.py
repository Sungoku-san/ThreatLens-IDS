import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, jsonify, redirect, url_for
from backend.config import Config
from backend.utils.helpers import init_db
from backend.utils.logger import logger


# Import Blueprints
from backend.routes.upload import upload_bp
from backend.routes.prediction import prediction_bp
from backend.routes.dashboard import dashboard_bp
from backend.routes.reports import reports_bp
from backend.routes.shap import shap_bp
from backend.routes.chat import chat_bp
from backend.routes.document import document_bp
from backend.routes.knowledge import knowledge_bp
from backend.routes.manual import manual_bp
from backend.routes.threat import threat_bp

def create_app():
    # Set directories relative to this file
    app = Flask(__name__, template_folder='templates', static_folder='static')
    
    # Load configuration
    app.config.from_object(Config)
    Config.init_app(app)
    
    # Initialize SQLite Database tables
    try:
        init_db()
        logger.info("SQLite database tables validated and seeded.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        
    # Register blueprints
    app.register_blueprint(upload_bp)
    app.register_blueprint(prediction_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(shap_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(document_bp)
    app.register_blueprint(knowledge_bp)
    app.register_blueprint(manual_bp)
    app.register_blueprint(threat_bp)
    
    # Web template routes
    @app.route('/')
    def index():
        return render_template('landing.html')
        
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # Simple hardcoded authentication credentials check
        if request.method == 'POST':
            if request.is_json:
                data = request.get_json()
                username = data.get('username')
                password = data.get('password')
            else:
                username = request.form.get('username')
                password = request.form.get('password')
                
            if username == "admin" and password == "password123":
                if request.is_json:
                    return jsonify({"status": "success", "redirect": url_for('dashboard')})
                return redirect(url_for('dashboard'))
            else:
                if request.is_json:
                    return jsonify({"status": "error", "message": "Invalid username or password"}), 401
                return render_template('login.html', error="Invalid username or password")
                
        return render_template('login.html')
        
    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')
        
    @app.errorhandler(404)
    def page_not_found(e):
        return jsonify({"status": "error", "message": "API endpoint or page not found."}), 404
        
    @app.errorhandler(500)
    def internal_server_error(e):
        return jsonify({"status": "error", "message": "Internal server error encountered."}), 500
        
    return app

app = create_app()

if __name__ == '__main__':
    logger.info("Starting AI-Based Intrusion Detection System backend service...")
    app.run(debug=True, host='127.0.0.1', port=5000)
