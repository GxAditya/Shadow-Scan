<div align="center">
  <img src="static/readme/shadow-scan-shield.svg" alt="ShadowScan shield logo" width="96" />
  <h1>ShadowScan</h1>
  <p>Static file analysis for malware triage, suspicious artifact detection, and scan history tracking.</p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+" />
    <img src="https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white" alt="Flask 3.x" />
    <img src="https://img.shields.io/badge/PostgreSQL-14-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL 14" />
    <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker Compose" />
    <img src="https://img.shields.io/badge/Analysis-Static%20Only-111827" alt="Static analysis only" />
    <img src="https://img.shields.io/badge/YARA-Rule%20Based-2563EB" alt="YARA rule based" />
  </p>
</div>

## Overview

ShadowScan is a Flask-based static analysis platform for inspecting suspicious files without executing them. It combines YARA rules, PE import analysis, document checks, and script inspection to produce a verdict, risk level, and historical scan record.

## Highlights

- Malware detection with 30+ YARA rules covering ransomware, trojans, backdoors, cryptominers, spyware, worms, rootkits, fileless patterns, and anti-analysis behavior.
- PE analysis with 85+ suspicious API import checks, including process injection, memory manipulation, anti-debugging, registry changes, and packer indicators.
- Script inspection for PowerShell, VBScript, JavaScript, Batch, and CMD files.
- Document-focused checks for PDFs and Office files, including macro, embedded object, JavaScript, and launch-action signals.
- Scan history persistence in PostgreSQL.
- Responsive web UI for file upload, analysis results, and history review.

## Supported File Types

- Executables: `exe`, `dll`
- Documents: `doc`, `docx`, `pdf`, `xls`, `xlsx`, `ppt`, `pptx`
- Scripts: `ps1`, `vbs`, `js`, `bat`, `cmd`
- Archives: `zip`, `rar`
- Text: `txt`

# Screenshots

![ShadowScan UI](static/readme/1.png)

## Stack

- Backend: Flask, SQLAlchemy
- Database: PostgreSQL
- Detection: YARA, `pefile`, `python-magic`
- Frontend: Bootstrap 5, Bootstrap Icons, vanilla JavaScript
- Deployment: Docker Compose

## Quick Start With Docker

Use Docker if you want the fastest path to a working environment.

```bash
git clone https://github.com/GxAditya/ShadowScan.git
cd ShadowScan
docker compose up -d --build
```

Open the application at `http://localhost:5000`.

Useful commands:

```bash
docker compose ps
docker compose logs -f web
docker compose down
```

## Local Development Setup

### Prerequisites

- Python 3.10 or newer
- PostgreSQL
- `libmagic` runtime installed on your system
- For Windows: Visual C++ Build Tools for `yara-python`

### 1. Clone the repository

```bash
git clone https://github.com/GxAditya/ShadowScan.git
cd ShadowScan
```

### 2. Create and activate a virtual environment

Linux and macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/malware_analysis
SESSION_SECRET=replace-this-with-a-secure-random-value
UPLOAD_FOLDER=/tmp/uploads
MAX_CONTENT_LENGTH=10485760
DEBUG=False
```

Environment variable reference:

| Variable | Required | Description |
| --- | --- | --- |
| `DATABASE_URL` | Yes | PostgreSQL connection string used by Flask SQLAlchemy |
| `SESSION_SECRET` | Yes | Secret key for Flask session handling |
| `UPLOAD_FOLDER` | No | Temporary folder for uploaded files |
| `MAX_CONTENT_LENGTH` | No | Max upload size in bytes, default `10485760` |
| `DEBUG` | No | Enables Flask debug mode when set to `True` |

### 5. Create the database schema

Make sure PostgreSQL is running and the target database exists, then initialize the tables:

```bash
python scripts/setup_db.py
```

### 6. Start the app

```bash
python main.py
```

The app will be available at `http://localhost:5000`.

## Windows Notes For YARA

If `yara-python` fails to install on Windows:

1. Install Visual C++ Build Tools from Microsoft.
2. During setup, select the C++ workload.
3. Re-run `pip install -r requirements.txt`.

If you still need a manual YARA build:

```cmd
git clone https://github.com/VirusTotal/yara.git
cd yara
python setup.py build
python setup.py install
```

## Custom YARA Rules

Use the helper script to add new rules:

```bash
python scripts/add_yara_rule.py --name "CustomRule" --description "Detects custom patterns" --severity "medium"
```

You can paste the rule content interactively or pass a file with `--file`.

## Security Notes

- Maximum upload size is 10 MB by default.
- Files are analyzed statically and are not executed.
- Uploaded files should be treated as sensitive and short-lived.
- Files are deleted after analysis.
- Path traversal is mitigated with secure filename handling.

## Operational Notes

- Docker deployment starts both the Flask app and PostgreSQL.
- The web service listens on `localhost:5000`.
- The database service listens on `localhost:5432`.
- Scan history is persisted in the Docker volume `postgres_data`.
