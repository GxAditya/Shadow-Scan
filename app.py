import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for
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
UPLOAD_FOLDER = '/tmp/uploads'
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB limit
ALLOWED_EXTENSIONS = {'exe', 'dll', 'doc', 'docx', 'pdf', 'xls', 'xlsx'}

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
        flash('No file selected', 'error')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))

    try:
        # Validate file
        if not validate_file(file):
            flash('Invalid file type or size', 'error')
            return redirect(url_for('index'))

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

        return render_template('results.html', results=results)

    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        flash('An error occurred while processing the file', 'error')
        return redirect(url_for('index'))

@app.route('/history')
def scan_history():
    scans = ScanLog.query.order_by(ScanLog.timestamp.desc()).all()
    return render_template('history.html', scans=scans)

@app.errorhandler(413)
def too_large(e):
    flash('File is too large. Maximum size is 10MB.', 'error')
    return redirect(url_for('index'))