import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
from utils.file_validator import validate_file
from utils.analyzer import analyze_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize SQLAlchemy
db = SQLAlchemy()

# File upload settings
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/uploads')
# Parse MAX_CONTENT_LENGTH properly, handling potential comment in the value
try:
    max_content_length = os.environ.get('MAX_CONTENT_LENGTH', '10485760')  # Default: 10MB
    MAX_CONTENT_LENGTH = int(max_content_length.split('#')[0].strip())
except (ValueError, AttributeError):
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # Default to 10MB if parsing fails
ALLOWED_EXTENSIONS = {'exe', 'dll', 'doc', 'docx', 'pdf', 'xls', 'xlsx', 'txt', 'ppt', 'pptx'}

# Create app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Configure upload settings
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize extensions
db.init_app(app)

# Models
class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(255), nullable=False)
    verdict = db.Column(db.String(50), nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    risk_factors = db.Column(db.JSON)
    analysis_details = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ScanLog {self.filename}>'

# Create tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        # flash('No file selected', 'error') # Flash messages might not work well with AJAX by default
        return jsonify({'error': 'No file selected'}), 400

    file = request.files['file']
    if file.filename == '':
        # flash('No file selected', 'error')
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Validate file
        if not validate_file(file):
            # flash('Invalid file type or size', 'error')
            return jsonify({'error': 'Invalid file type or size'}), 400

        # Secure the filename and save
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Analyze the file
        results = analyze_file(filepath)

        # Log the scan results
        scan_log = ScanLog(
            filename=filename,
            file_type=results['file_type'],
            verdict=results['verdict'],
            risk_level=results.get('risk_level', 'unknown'),
            risk_factors=results['risk_factors'],
            analysis_details=results.get('analysis_details', {})
        )
        db.session.add(scan_log)
        db.session.commit()

        # Clean up
        os.remove(filepath)

        results_html = render_template('results.html', results=results)
        return jsonify({'html_content': results_html})
        # Alternatively, to redirect to a new page showing results:
        # session['analysis_results'] = results # Store results in session
        # return jsonify({'redirect_url': url_for('show_results')})

    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        # flash('An error occurred while processing the file', 'error')
        return jsonify({'error': 'An error occurred while processing the file'}), 500

@app.route('/history')
def scan_history():
    scans = ScanLog.query.order_by(ScanLog.timestamp.desc()).all()
    return render_template('history.html', scans=scans)

@app.errorhandler(413)
def too_large(e):
    # flash('File is too large. Maximum size is 10MB.', 'error')
    if request.is_json or (request.headers.get('X-Requested-With') == 'XMLHttpRequest'):
        return jsonify(error='File is too large. Maximum size is 10MB.'), 413
    # Fallback for non-AJAX requests or if client doesn't specify accept json
    flash('File is too large. Maximum size is 10MB.', 'error')
    return redirect(url_for('index'))