# LOGSHIELD — AI-Assisted Log-Based Intrusion Detection System (v0.5)

LOGSHIELD is a serious, lightweight cybersecurity platform designed to ingest security log telemetry (JSON, CSV, JSONL, Syslog), evaluate rule-based threat indicators, run scikit-learn IsolationForest anomaly detection, correlate multi-stage attack chains, and compute deterministic risk scores.

## Architecture

```
  Log Ingestion File Upload (PRIMARY INPUT: JSON, CSV, Syslog)
                              OR
  Controlled Security Event Simulator (Testing Tool - Tkinter)
                              ↓
                  Log Telemetry Storage (data/logs.json)
                              ↓
Extensible OOP Parser Architecture (backend/parser.py: JSON / CSV / Syslog)
                              ↓
   Rule Engine + AI IsolationForest Detector (backend/detector.py)
                              ↓
       Event Correlation & Risk Engine (backend/risk_engine.py)
                              ↓
              FastAPI Backend (backend/main.py)
                              ↓
            Live Dynamic Security Dashboard (frontend/)
```

## Features

- **Primary Input Ingestion**: Ingest real log telemetry files (JSON, CSV, JSONL, Syslog/TXT) directly into the processing pipeline with overwrite or append modes.
- **Extensible Parser Architecture**: OOP `BaseLogParser` interface with `JSONLogParser`, `CSVLogParser`, and `SyslogParser`, enabling easy addition of future log formats.
- **Controlled Security Event Simulator**: Lightweight Tkinter testing interface to trigger synthetic security test streams into the unified detection pipeline.
- **Rule Engine & AI Outlier Detection**: Hybrid detection combining expert signature rules with scikit-learn IsolationForest unsupervised anomaly detection.
- **Dynamic Risk & Attack Correlation**: Real-time correlation of attack chains, severity scoring, confidence rating, and human-readable threat explanations without static or hardcoded results.

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Application
Run the launcher script:
```cmd
run.bat
```
Or start backend manually:
```bash
cd logshield
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
And launch the Tkinter controlled security event simulator GUI (for testing):
```bash
python simulator/simulator.py
```

### 3. Open Dashboard
Navigate to `http://127.0.0.1:8000` in your web browser.

## API Endpoints

- `GET /api/health`: Health status & version.
- `GET /api/logs`: Current raw log events.
- `GET /api/analyze`: Comprehensive analysis (Rules, IsolationForest AI, Incidents, Risk Scores).
- `POST /api/upload`: Upload JSON, CSV, JSONL, or Syslog log files (supports `mode=overwrite` or `mode=append`).
- `POST /api/reset`: Reset all logs to empty state.

