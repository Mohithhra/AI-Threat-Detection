# 🛡️ SentinelEML 3.0 - Next-Gen AI Email Threat Intelligence, Quishing & Cyber Crime Platform

An end-to-end cybersecurity email threat intelligence and forensic platform featuring **AI Quishing (QR Code Phishing) Scanning**, **Zero-Shot NLP Social Engineering Classification**, **Indian National Cyber Crime Reporting Portal (NCRP) Auto-FIR Integration**, **Dark Tracer Canary Honeypots**, **Browser Extension**, **Realtime IMAP Inbox Listener**, and **Docker Deployment**.

---

## 👥 Team Roles & Modular Deliverables

| Teammate | Assigned Role | Deliverable Module | Status |
| :--- | :--- | :--- | :---: |
| **Cyber Leader** | Header Parser, DNS Auth & Link Extractor | `app/modules/cyber_leader/` | ✅ Complete |
| **Cyber 2** | VirusTotal v3 & AbuseIPDB v2 Threat Intel | `app/modules/cyber_2/` | ✅ Complete |
| **AIDS Member** | Explainable Rule-Based Risk Scorer (0-100) | `app/modules/aids_member/` | ✅ Complete |
| **CSE 3** | IP Geolocation (`ip-api.com`) & PDF Generator | `app/modules/cse3/` | ✅ Complete |
| **CSE 2** | Modern Cybersecurity Dashboard (Tailwind + Leaflet) | `frontend/` | ✅ Complete |
| **CSE 1 (Backend)** | AI Quishing, NCRP FIR Portal, Dark Tracer & API | `app/main.py` & `app/models.py` | ✅ Complete |

---

## 🚀 Quickstart Guide

### 1. Install Dependencies
```bash
cd email-threat-analyzer
pip install -r requirements.txt
```

### 2. Run Platform
```bash
python run.py
```
Open browser at: **[http://localhost:8000](http://localhost:8000)**  
Interactive Swagger API documentation: **[http://localhost:8000/docs](http://localhost:8000/docs)**

---

## 🐳 Docker Deployment

To launch the platform in a containerized environment:

```bash
docker-compose up --build
```

---

## 🔌 Browser Extension (Chrome Manifest V3)

1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `chrome_extension/` folder inside `email-threat-analyzer/`.
4. Open any email in Gmail or Outlook, click the SentinelEML extension icon, and click **Scan Active Email Body**!

---

## 📩 Real-Time IMAP / Gmail Inbox Listener

To run real-time inbox monitoring for unseen emails:
```python
from app.modules.imap_listener import RealtimeIMAPMonitor
from app.database import SessionLocal

monitor = RealtimeIMAPMonitor("imap.gmail.com")
if monitor.connect("your_email@gmail.com", "your_app_password"):
    db = SessionLocal()
    results = monitor.fetch_unread_emails(db)
```

---

## 📂 Project Architecture

```
email-threat-analyzer/
├── app/
│   ├── database.py                 # SQLite DB session
│   ├── models.py                   # SQLAlchemy ORM models
│   ├── main.py                     # Backend Orchestrator & REST API
│   └── modules/
│       ├── ai_nlp/                 # AI Threat Classifier & Quishing QR Scanner
│       ├── cyber_crime/            # NCRP Indian Cyber Portal FIR Engine & PDF Dossier
│       ├── dark_tracer/            # Honeypot Canary Pixel & Tracking Link Generator
│       ├── copilot/                # Interactive Forensic AI Assistant
│       ├── cyber_leader/           # Header parser & Link extractor
│       ├── cyber_2/                # VirusTotal & AbuseIPDB client
│       ├── aids_member/            # Rule-based explainable risk scorer
│       ├── cse3/                   # IP Geolocation & PDF report generator
│       ├── imap_listener.py        # Real-time inbox monitor
│       └── threat_export/          # STIX 2.1, CSV, Snort & YARA exporter
├── chrome_extension/               # Chrome Manifest V3 Webmail Scanner Extension
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── content_script.js
├── frontend/                       # Cybersecurity SOC Command Center UI
├── samples/                        # Pre-built test emails (.eml)
├── reports/                        # Automatically generated PDF reports
├── Dockerfile                      # Container definition
├── docker-compose.yml              # Container orchestration
├── test_pipeline.py                # Automated unittest suite
└── run.py                          # Single-command launcher
```
