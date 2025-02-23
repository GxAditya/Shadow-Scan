# Static File Analysis Platform

A comprehensive web-based static file analysis platform for advanced malware detection, offering detailed risk factor reporting and secure file analysis capabilities.

## Features

- Static analysis of multiple file formats (EXE, DLL, DOC, DOCX, PDF, XLS, XLSX)
- YARA rules integration for malware pattern detection
- Detailed risk factor analysis and reporting
- PE file analysis with comprehensive security checks
- Document analysis for potential threats
- Scan history tracking with PostgreSQL database
- Dark-themed responsive web interface

## Technical Stack

- **Backend**: Python (Flask)
- **Database**: PostgreSQL
- **Analysis Tools**: 
  - YARA for pattern matching
  - pefile for PE file analysis
  - python-magic for file type detection
- **Frontend**: Bootstrap 5 with dark theme

## Setup Instructions

1. Clone the repository:
```bash
git clone https://github.com/GxAditya/Static-File-Analysis
cd static-file-analysis
```

2. Set up environment variables:
```bash
export DATABASE_URL="your-postgresql-database-url"
export SESSION_SECRET="your-session-secret"
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python main.py
```

The application will be available at `http://localhost:5000`

## Security Considerations

- Maximum file size: 10MB
- Files are analyzed using static analysis only
- No sensitive or personal files should be uploaded
- All uploaded files are automatically deleted after analysis
