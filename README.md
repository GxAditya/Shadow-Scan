# ShadowScan: Static File Analysis Platform

ShadowScan is a comprehensive web-based static file analysis platform for advanced malware detection, offering detailed risk factor reporting and secure file analysis capabilities.

## Features

- **Comprehensive Malware Detection** - 30+ YARA rules covering all major malware families:
  - Ransomware, Trojans, Backdoors, Cryptominers
  - Keyloggers, Spyware, Worms, Viruses
  - Rootkits, Web Shells, Fileless malware
  - Anti-analysis techniques and obfuscation
  
- **Enhanced PE File Analysis** - 85+ suspicious API imports detection with severity levels:
  - Memory operations, process injection, code execution
  - Network operations, registry manipulation
  - Anti-debugging, anti-VM techniques
  - Packer detection (UPX, MPRESS, Themida, VMProtect, etc.)
  
- **Script File Analysis** - NEW support for PowerShell, VBScript, JavaScript, and Batch files:
  - Code execution and download detection
  - Obfuscation and encoding detection
  - Command injection patterns
  
- **Document Analysis** - Enhanced detection for malicious documents:
  - PDF: JavaScript, auto-actions, launch actions
  - Office: Macros, embedded objects, OLE analysis
  
- **Multi-Format Support** - Static analysis of multiple file formats:
  - Executables: EXE, DLL
  - Documents: DOC, DOCX, PDF, XLS, XLSX, PPT, PPTX
  - Scripts: PS1, VBS, JS, BAT, CMD
  - Archives: ZIP, RAR
  - Text: TXT
  
- **Advanced Risk Assessment** - 4-level risk system (Critical/High/Medium/Low)
- **Scan History Tracking** - PostgreSQL database for historical analysis
- **Dark-themed Responsive Web Interface**
- **Secure File Handling** - Automatic deletion after analysis

## Technical Stack

- **Backend**: Python (Flask)
- **Database**: PostgreSQL
- **Analysis Tools**: 
  - YARA for pattern matching
  - pefile for PE file analysis
  - python-magic for file type detection
- **Frontend**: Bootstrap 5 with dark theme and JavaScript for interactive elements

## Setup Instructions

### Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- For Windows users: Visual C++ Build Tools for yara-python

### Installation

1. Clone the repository:
```bash
git clone https://github.com/GxAditya/Static-File-Analysis
cd static-file-analysis
```

2. Set up environment variables:

For Windows:
```cmd
set DATABASE_URL=your-postgresql-database-url
set SESSION_SECRET=your-session-secret
```

For Linux/Mac:
```bash
export DATABASE_URL="your-postgresql-database-url"
export SESSION_SECRET="your-session-secret"
```

Alternatively, create a `.env` file in the project root with these variables.

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Windows-specific YARA installation

YARA requires additional setup on Windows:

1. Install Visual C++ Build Tools:
   - Download from [Microsoft Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - Select "C++ build tools" during installation

2. Install YARA from source:
   ```cmd
   git clone https://github.com/VirusTotal/yara.git
   cd yara
   python setup.py build
   python setup.py install
   ```

### Running the Application

1. Initialize the database:
```bash
python scripts/setup_db.py
```

2. Run the application:
```bash
python main.py
```

The application will be available at `http://localhost:5000`

## Docker Deployment

For easier deployment, you can use Docker Compose:

```bash
docker-compose up -d
```

This will start both the web application and PostgreSQL database.

## Adding Custom YARA Rules

You can add custom YARA rules using the provided script:

```bash
python scripts/add_yara_rule.py --name "CustomRule" --description "Detects custom patterns" --severity "medium"
```

Then enter your YARA rule content or provide a file with the `--file` option.

## Security Considerations

- Maximum file size: 10MB
- Files are analyzed using static analysis only
- No sensitive or personal files should be uploaded
- All uploaded files are automatically deleted after analysis
- File type validation to prevent malicious uploads
- Secure filename handling to prevent path traversal attacks

## Performance Considerations

- Asynchronous file processing for better user experience
- Efficient static analysis algorithms to minimize processing time
- Database connection pooling for improved concurrent request handling
