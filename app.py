import os
from flask import Flask, render_template, request, jsonify, redirect, url_for

app = Flask(__name__)

# Mock database user
USER_CREDENTIALS = {
    "username": "admin",
    "password": "password123"
}

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Accept either form post or JSON post
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
            
        if username == USER_CREDENTIALS["username"] and password == USER_CREDENTIALS["password"]:
            if request.is_json:
                return jsonify({"status": "success", "redirect": url_for('dashboard')})
            return redirect(url_for('dashboard'))
        else:
            if request.is_json:
                return jsonify({"status": "error", "message": "Invalid credentials"}), 401
            return render_template('login.html', error="Invalid username or password")
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Flask mock API endpoints to simulate backend functionality
@app.route('/api/upload', methods=['POST'])
def upload_dataset():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    # In a real app, we would process/parse the CSV here.
    # For this UI project, we'll return dataset statistics.
    return jsonify({
        "status": "success",
        "dataset_name": file.filename,
        "size": f"{len(file.read()) / 1024:.2f} KB",
        "rows": 12500,
        "columns": 42,
        "message": "Dataset successfully uploaded and validated."
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
