import os
import sys
import uvicorn

if __name__ == "__main__":
    # Ensure current directory is in PYTHONPATH
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    print("=" * 70)
    print(" [***] SENTINEL EML - EMAIL THREAT INTELLIGENCE PLATFORM")
    print("=" * 70)
    print(" [+] Teammate Modules Loaded:")
    print("     - Cyber Leader: Header Parser, SPF/DKIM/DMARC DNS, URL Extractor")
    print("     - Cyber 2     : VirusTotal & AbuseIPDB Threat Intel Client")
    print("     - AIDS Member : 0-100 Explainable Rule-Based Risk Scorer")
    print("     - CSE 3       : IP Geolocation (ip-api.com) & PDF Generator")
    print("     - CSE 2       : Cyberpunk Dark Dashboard (Tailwind + Leaflet)")
    print("     - CSE 1 (You) : FastAPI Backend Orchestrator & SQLite Database")
    print("=" * 70)
    print(" [*] Server launching at: http://localhost:8000")
    print(" [*] Interactive API Docs: http://localhost:8000/docs")
    print("=" * 70)

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
