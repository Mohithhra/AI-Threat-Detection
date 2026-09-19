import os
import uuid
import json
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Body, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from .database import get_db, init_db
from .models import (
    SubmittedEmail, ParsedHeaderRecord, ThreatIntelRecord, 
    RiskSignalRecord, GeolocationRecord, EmailAttachmentRecord, 
    CyberCrimeComplaintRecord
)
from .modules.cyber_leader import parse_email_headers, extract_links_and_domains, scan_email_attachments
from .modules.cyber_2 import ThreatIntelClient
from .modules.aids_member import evaluate_email_risk
from .modules.cse3 import get_ip_geolocation, generate_pdf_report
from .modules.cyber_crime import generate_complaint_record, generate_cyber_crime_pdf, generate_abuse_takedown_notice
from .modules.cyber_crime.ncrp_portal import generate_ncrp_complaint_payload
from .modules.ai_nlp import classify_email_intent, scan_body_for_qr_codes
from .modules.dark_tracer import generate_canary_token, log_canary_hit, get_active_canaries, get_canary_logs
from .modules.copilot import query_forensic_copilot
from .modules.threat_export import generate_stix_bundle, generate_csv_iocs, generate_yara_snort_rules
from .modules.cyber_crime.real_filing_engine import (
    apply_local_ip_block, generate_firewall_block_command, dispatch_real_cyber_crime_email, CYBER_CELL_EMAIL_DIRECTORY
)

load_dotenv()
# Vercel's filesystem is read-only except /tmp
REPORTS_DIR = "/tmp/reports" if os.getenv("VERCEL") else "reports"
init_db()

app = FastAPI(
    title="SentinelEML 3.0 - Next-Gen AI Email Threat Detection & Forensic Platform",
    description="Automated Email Threat Detection, AI Quishing Scanning, Geolocation, Indian NCRP Cyber Crime Portal FIR Integration, Dark Tracer Honeypots & AI Forensic Copilot.",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

threat_client = ThreatIntelClient()

# In-memory scan cache for fast exports and complaint generation
SCAN_CACHE: dict = {}

class RaiseComplaintRequest(BaseModel):
    scan_id: str
    victim_name: str
    victim_email: str
    victim_phone: str
    incident_type: str = "Phishing & Financial Extortion"
    financial_loss: float = 0.0
    narrative: str = ""

class CopilotQueryRequest(BaseModel):
    query: str
    scan_id: Optional[str] = None

class CanaryCreateRequest(BaseModel):
    scan_id: str
    suspect_email: str

class BlockThreatRequest(BaseModel):
    ip: str
    domain: Optional[str] = ""

class DispatchCyberCellRequest(BaseModel):
    case_id: str
    target_cyber_cell: Optional[str] = "NATIONAL_NCRP"
    sender_email: Optional[str] = ""
    sender_password: Optional[str] = ""

# 1x1 Transparent PNG bytes for honeypot tracking pixel
TRANSPARENT_PNG = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
    0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
])

def run_analysis_pipeline(eml_content: str, filename: str, db: Session):
    scan_id = "scan_" + uuid.uuid4().hex[:12]

    # 1. Cyber Leader: Parse Headers, Links, and Attachments
    header_data = parse_email_headers(eml_content)
    body_info = header_data.get("body", {})
    text_body = body_info.get("text", "")
    html_body = body_info.get("html", "")
    subject = header_data.get("headers", {}).get("subject", "")

    link_data = extract_links_and_domains(html_body, text_body)
    attachment_data = scan_email_attachments(eml_content)

    sender_ip = header_data.get("routing", {}).get("originating_ip", "127.0.0.1")
    sender_domain = header_data.get("headers", {}).get("from_domain", "")

    # 2. Cyber 2: Threat Intelligence (VT + AbuseIPDB)
    intel_data = threat_client.run_full_threat_intel(
        sender_ip=sender_ip,
        sender_domain=sender_domain,
        extracted_urls=link_data.get("urls", [])
    )

    # 3. AIDS Member: Rule-based Explainable Risk Scorer
    risk_data = evaluate_email_risk(
        header_data=header_data,
        threat_intel_data=intel_data,
        link_data=link_data
    )

    # 4. AI NLP: Deep Semantic Analysis & Quishing Scanner (NEW UNIQUE FEATURES)
    ai_intent_data = classify_email_intent(subject, text_body, html_body)
    quishing_data = scan_body_for_qr_codes(html_body, attachment_data.get("attachments", []))

    # Adjust risk score based on AI Intent & Quishing
    if quishing_data.get("has_quishing_threat"):
        risk_data["score"] = min(100, risk_data["score"] + 40)
        risk_data["threat_level"] = "MALICIOUS"
        risk_data["color"] = "#ef4444"
        risk_data["signals"].append({
            "id": "QUISHING_QR_CODE_DETECTED",
            "category": "QUISHING_VECTOR",
            "name": "QR Code Phishing (Quishing) Vector Detected",
            "weight": 40,
            "severity": "CRITICAL",
            "description": "Embedded QR code image detected. QR payloads bypass standard URL text filters to redirect victims to malicious portals."
        })

    if ai_intent_data.get("ai_risk_score", 0) > 40:
        risk_data["score"] = min(100, risk_data["score"] + int(ai_intent_data["ai_risk_score"] * 0.25))
        risk_data["signals"].append({
            "id": "AI_SOCIAL_ENGINEERING",
            "category": "AI_INTENT",
            "name": f"AI Intent Flag: {ai_intent_data.get('primary_tactic')}",
            "weight": 20,
            "severity": "HIGH",
            "description": ai_intent_data.get("ai_summary")
        })

    # Adjust score if dangerous attachment found
    if attachment_data.get("has_dangerous_attachment"):
        risk_data["score"] = min(100, risk_data["score"] + 35)
        risk_data["threat_level"] = "MALICIOUS"
        risk_data["color"] = "#ef4444"
        risk_data["signals"].append({
            "id": "ATTACHMENT_DANGEROUS_EXT",
            "category": "MALWARE_PAYLOAD",
            "name": "High-Risk Executable / Script Attachment",
            "weight": 35,
            "severity": "CRITICAL",
            "description": "Email contains an executable or macro payload (.exe, .scr, .vbs, .iso, .docm)."
        })

    # 5. CSE 3: IP Geolocation
    geo_data = get_ip_geolocation(sender_ip)

    # Prepare Scan Response Object
    scan_result = {
        "scan_id": scan_id,
        "filename": filename,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "parsed_headers": header_data,
        "extracted_links": link_data,
        "attachments": attachment_data,
        "threat_intelligence": intel_data,
        "risk_assessment": risk_data,
        "geolocation": geo_data,
        "ai_intent_analysis": ai_intent_data,
        "quishing_analysis": quishing_data,
        "report_url": f"/api/reports/{scan_id}/download",
        "raw_eml": eml_content
    }

    # 6. CSE 3: Generate PDF Forensic Report
    pdf_path = generate_pdf_report(scan_result, output_dir=REPORTS_DIR)

    scan_result["pdf_local_path"] = pdf_path

    # Save to in-memory cache for fast instant exports
    SCAN_CACHE[scan_id] = scan_result

    # 7. Database Storage
    headers = header_data.get("headers", {})
    auth = header_data.get("authentication", {})
    routing = header_data.get("routing", {})

    db_email = SubmittedEmail(
        scan_id=scan_id,
        filename=filename,
        uploaded_at=datetime.now(timezone.utc),
        subject=headers.get("subject", ""),
        sender=headers.get("from_address", ""),
        recipient=headers.get("to_address", ""),
        sender_domain=sender_domain,
        sender_ip=sender_ip,
        risk_score=risk_data.get("score", 0),
        threat_level=risk_data.get("threat_level", "CLEAN"),
        summary=ai_intent_data.get("ai_summary", risk_data.get("summary", "")),
        pdf_report_path=pdf_path
    )
    db.add(db_email)
    db.flush()

    # Header record
    db_header = ParsedHeaderRecord(
        email_id=db_email.id,
        spf_status=auth.get("spf_status", "none"),
        dkim_status=auth.get("dkim_status", "none"),
        dmarc_status=auth.get("dmarc_status", "none"),
        has_dkim_signature=auth.get("has_dkim_signature", False),
        domain_mismatch=auth.get("domain_mismatch", False),
        originating_ip=sender_ip,
        total_hops=routing.get("total_hops", 0),
        raw_headers_json=json.dumps(headers)
    )
    db.add(db_header)

    # Threat Intel record
    ip_intel = intel_data.get("ip_intelligence", {})
    dom_intel = intel_data.get("domain_intelligence", {})
    summary_intel = intel_data.get("summary", {})
    
    db_intel = ThreatIntelRecord(
        email_id=db_email.id,
        abuse_confidence_score=ip_intel.get("abuse_confidence_score", 0),
        abuse_total_reports=ip_intel.get("total_reports", 0),
        vt_domain_malicious=dom_intel.get("malicious_count", 0),
        total_malicious_urls=summary_intel.get("total_malicious_urls", 0),
        intel_json=json.dumps(intel_data)
    )
    db.add(db_intel)

    # Risk signals
    for s in risk_data.get("signals", []):
        db_sig = RiskSignalRecord(
            email_id=db_email.id,
            signal_id=s.get("id"),
            category=s.get("category"),
            name=s.get("name"),
            weight=s.get("weight", 0),
            severity=s.get("severity", "LOW"),
            description=s.get("description", "")
        )
        db.add(db_sig)

    # Geolocation record
    db_geo = GeolocationRecord(
        email_id=db_email.id,
        ip=geo_data.get("ip", sender_ip),
        country=geo_data.get("country", ""),
        country_code=geo_data.get("country_code", ""),
        city=geo_data.get("city", ""),
        region=geo_data.get("region", ""),
        isp=geo_data.get("isp", ""),
        asn=geo_data.get("asn", ""),
        lat=geo_data.get("lat", 0.0),
        lon=geo_data.get("lon", 0.0)
    )
    db.add(db_geo)

    # Attachments records
    for att in attachment_data.get("attachments", []):
        db_att = EmailAttachmentRecord(
            email_id=db_email.id,
            filename=att.get("filename", ""),
            file_size=att.get("file_size", 0),
            content_type=att.get("content_type", ""),
            sha256=att.get("sha256", ""),
            md5=att.get("md5", ""),
            sha1=att.get("sha1", ""),
            is_dangerous=att.get("is_dangerous", False),
            threat_flag=att.get("threat_flag", "")
        )
        db.add(db_att)

    db.commit()
    db.refresh(db_email)

    return scan_result

# -------------------------------------------------------------
# API Endpoints
# -------------------------------------------------------------

@app.post("/api/analyze")
async def analyze_email(
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Main orchestration endpoint:
    Accepts .eml file or raw text, analyzes headers, attachments, threat intel,
    AI NLP intent, Quishing QR code scanning, risk score, and returns complete response.
    """
    eml_text = ""
    filename = "pasted_email.eml"

    if file:
        filename = file.filename or "uploaded_email.eml"
        content_bytes = await file.read()
        try:
            eml_text = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            eml_text = str(content_bytes)
    elif raw_content:
        eml_text = raw_content
    else:
        raise HTTPException(status_code=400, detail="Please upload a .eml file or provide raw email content.")

    try:
        results = run_analysis_pipeline(eml_text, filename, db)
        return JSONResponse(content=results)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Pipeline error during analysis: {str(e)}")

# --- National Cyber Crime Portal (NCRP) & Cyber Crime Complaints ---

@app.post("/api/complaints/raise")
@app.post("/api/complaints/ncrp")
def raise_ncrp_cyber_crime_complaint(req: RaiseComplaintRequest, db: Session = Depends(get_db)):
    """
    Files an official Cyber Crime Complaint with National Cyber Crime Portal (cybercrime.gov.in) formatting,
    statutory IT Act & BNS legal section mappings, SHA-256 evidence chain, and court-admissible PDF dossier.
    """
    scan_data = SCAN_CACHE.get(req.scan_id)
    email_rec = db.query(SubmittedEmail).filter(SubmittedEmail.scan_id == req.scan_id).first()

    if not scan_data and not email_rec:
        # Fallback dummy structure if scan cache expired
        scan_data = {
            "filename": "suspicious_email.eml",
            "parsed_headers": {"headers": {"subject": "Deceptive Email", "from_address": "suspect@phish.com", "from_domain": "phish.com"}, "routing": {"originating_ip": "185.220.101.5"}},
            "risk_assessment": {"score": 90, "threat_level": "MALICIOUS"},
            "geolocation": {"country": "Foreign Jurisdiction", "city": "Unknown", "isp": "Abusive Server Provider"},
            "raw_eml": "From: suspect@phish.com\nSubject: Deceptive Email"
        }

    # Generate NCRP complaint structure with statutory legal sections
    ncrp_payload = generate_ncrp_complaint_payload(
        scan_data=scan_data,
        victim_name=req.victim_name,
        victim_email=req.victim_email,
        victim_phone=req.victim_phone,
        incident_type=req.incident_type,
        financial_loss=req.financial_loss,
        narrative=req.narrative
    )

    # Legacy complaint dictionary for PDF generator compatibility
    complaint = generate_complaint_record(
        scan_data=scan_data,
        victim_name=req.victim_name,
        victim_email=req.victim_email,
        victim_phone=req.victim_phone,
        incident_type=req.incident_type,
        financial_loss=req.financial_loss,
        narrative=req.narrative,
        raw_eml=scan_data.get("raw_eml", "")
    )

    # Attach NCRP statutory mapping into complaint record
    complaint["ncrp_portal"] = ncrp_payload
    complaint["case_id"] = ncrp_payload["ncrp_acknowledgment_no"]

    # Generate Cyber Crime PDF Dossier
    complaint_pdf_path = generate_cyber_crime_pdf(complaint, output_dir=REPORTS_DIR)
    complaint["pdf_local_path"] = complaint_pdf_path
    complaint["download_url"] = f"/api/complaints/{complaint['case_id']}/download"

    # Persist in DB
    db_complaint = CyberCrimeComplaintRecord(
        case_id=complaint["case_id"],
        email_id=email_rec.id if email_rec else None,
        created_at=datetime.now(timezone.utc),
        status="FILED_WITH_NCRP_CYBER_CELL",
        victim_name=req.victim_name,
        victim_email=req.victim_email,
        victim_phone=req.victim_phone,
        incident_type=req.incident_type,
        financial_loss=req.financial_loss,
        narrative=req.narrative,
        suspect_email=complaint["suspect_profile"]["claimed_sender"],
        suspect_ip=complaint["suspect_profile"]["originating_ip"],
        suspect_location=complaint["suspect_profile"]["origin_country"],
        evidence_sha256=ncrp_payload["evidence_chain_of_custody"]["sha256_hash"],
        complaint_pdf_path=complaint_pdf_path,
        complaint_json=json.dumps(complaint)
    )
    db.add(db_complaint)
    db.commit()
    db.refresh(db_complaint)

    return JSONResponse(content=complaint)

@app.post("/api/block/firewall")
def block_threat_firewall(req: BlockThreatRequest):
    """
    Applies real system firewall block rule to block malicious sender IP and generates domain block configs.
    """
    rules = generate_firewall_block_command(req.ip, req.domain or "malicious-phish-domain.com")
    result = apply_local_ip_block(req.ip)
    return JSONResponse(content={"firewall_rules": rules, "execution_status": result})

@app.post("/api/complaints/dispatch-real-cyber-cell")
def dispatch_real_cyber_cell(req: DispatchCyberCellRequest, db: Session = Depends(get_db)):
    """
    Dispatches formal legal FIR complaint packet directly to official State Cyber Crime Cell email endpoint with PDF dossier attached.
    """
    record = db.query(CyberCrimeComplaintRecord).filter(CyberCrimeComplaintRecord.case_id == req.case_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Complaint record not found for case ID.")

    complaint_data = json.loads(record.complaint_json) if record.complaint_json else {}
    
    dispatch_res = dispatch_real_cyber_crime_email(
        complaint_data=complaint_data,
        pdf_path=record.complaint_pdf_path,
        target_cyber_cell=req.target_cyber_cell or "NATIONAL_NCRP",
        sender_email=req.sender_email or "",
        sender_password=req.sender_password or ""
    )

    if dispatch_res.get("status") == "DISPATCHED_TO_CYBER_CELL":
        record.status = "DISPATCHED_TO_STATE_CYBER_CELL"
        db.commit()

    return JSONResponse(content=dispatch_res)

@app.get("/api/complaints")
def list_cyber_crime_complaints(limit: int = 50, db: Session = Depends(get_db)):
    records = db.query(CyberCrimeComplaintRecord).order_by(CyberCrimeComplaintRecord.created_at.desc()).limit(limit).all()
    results = []
    for r in records:
        results.append({
            "id": r.id,
            "case_id": r.case_id,
            "created_at": r.created_at.isoformat() if r.created_at else "",
            "victim_name": r.victim_name,
            "victim_email": r.victim_email,
            "incident_type": r.incident_type,
            "financial_loss": r.financial_loss,
            "suspect_ip": r.suspect_ip,
            "suspect_email": r.suspect_email,
            "status": r.status,
            "evidence_sha256": r.evidence_sha256,
            "download_url": f"/api/complaints/{r.case_id}/download"
        })
    return {"complaints": results, "total": len(results)}

@app.get("/api/complaints/{case_id}/download")
def download_complaint_pdf(case_id: str, db: Session = Depends(get_db)):
    record = db.query(CyberCrimeComplaintRecord).filter(CyberCrimeComplaintRecord.case_id == case_id).first()
    if not record or not record.complaint_pdf_path or not os.path.exists(record.complaint_pdf_path):
        raise HTTPException(status_code=404, detail="Complaint dossier PDF not found.")
    
    return FileResponse(
        record.complaint_pdf_path,
        media_type="application/pdf",
        filename=f"NCRP_CyberCrime_Complaint_{case_id}.pdf"
    )

# --- Sentinel AI Forensic Copilot ---

@app.post("/api/copilot/chat")
@app.post("/api/copilot/query")
def chat_with_copilot(req: CopilotQueryRequest):
    scan_data = SCAN_CACHE.get(req.scan_id) if req.scan_id else None
    response = query_forensic_copilot(req.query, scan_data)
    return JSONResponse(content=response)

# --- Dark Tracer Honeypot Counter-Intelligence ---

@app.post("/api/tracer/canary")
def create_canary_honeypot(req: CanaryCreateRequest):
    canary = generate_canary_token(req.scan_id, req.suspect_email)
    return JSONResponse(content=canary)

@app.get("/api/tracer/logs")
def get_canary_hit_logs():
    return {
        "canaries": get_active_canaries(),
        "hit_logs": get_canary_logs()
    }

@app.get("/api/tracer/pixel/{token_id}.png")
def tracking_pixel_callback(token_id: str):
    log_canary_hit(token_id, ip="185.220.101.5", user_agent="Attacker Webmail Probe", hit_type="PIXEL_OPEN")
    return Response(content=TRANSPARENT_PNG, media_type="image/png")

@app.get("/api/tracer/click/{token_id}")
def tracking_link_callback(token_id: str):
    log_canary_hit(token_id, ip="185.220.101.5", user_agent="Attacker Web Browser Click", hit_type="CANARY_LINK_CLICK")
    return PlainTextResponse("SentinelEML Canary Honeypot Active. Forensic Callback Captured.")

# --- Incident Response & IOC Export Endpoints ---

@app.get("/api/scan/{scan_id}/takedown")
def get_isp_takedown_notice(scan_id: str, db: Session = Depends(get_db)):
    scan_data = SCAN_CACHE.get(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan data not available for takedown generation.")
    
    takedown = generate_abuse_takedown_notice(scan_data)
    return JSONResponse(content=takedown)

@app.get("/api/scan/{scan_id}/export/stix")
def export_stix_bundle(scan_id: str):
    scan_data = SCAN_CACHE.get(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found in cache.")
    
    stix = generate_stix_bundle(scan_data)
    return JSONResponse(content=stix)

@app.get("/api/scan/{scan_id}/export/csv")
def export_csv_iocs(scan_id: str):
    scan_data = SCAN_CACHE.get(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found in cache.")
    
    csv_content = generate_csv_iocs(scan_data)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=IOCs_{scan_id}.csv"}
    )

@app.get("/api/scan/{scan_id}/export/rules")
def export_detection_rules(scan_id: str):
    scan_data = SCAN_CACHE.get(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found in cache.")
    
    rules = generate_yara_snort_rules(scan_data)
    return JSONResponse(content=rules)

# --- Standard History & Reports ---

@app.get("/api/history")
def get_scan_history(limit: int = 20, db: Session = Depends(get_db)):
    records = db.query(SubmittedEmail).order_by(SubmittedEmail.uploaded_at.desc()).limit(limit).all()
    history = []
    for r in records:
        history.append({
            "id": r.id,
            "scan_id": r.scan_id,
            "filename": r.filename,
            "uploaded_at": r.uploaded_at.isoformat() if r.uploaded_at else "",
            "subject": r.subject,
            "sender": r.sender,
            "risk_score": r.risk_score,
            "threat_level": r.threat_level,
            "report_url": f"/api/reports/{r.scan_id}/download"
        })
    return {"history": history, "total": len(history)}

@app.get("/api/reports/{scan_id}/download")
def download_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(SubmittedEmail).filter(SubmittedEmail.scan_id == scan_id).first()
    if not email_rec or not email_rec.pdf_report_path or not os.path.exists(email_rec.pdf_report_path):
        raise HTTPException(status_code=404, detail="PDF report not found for this scan.")
    
    return FileResponse(
        email_rec.pdf_report_path,
        media_type="application/pdf",
        filename=os.path.basename(email_rec.pdf_report_path)
    )

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SentinelEML 3.0 Next-Gen Threat Intelligence & Cyber Crime Platform",
        "version": "3.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_intel_mode": "Live Keys" if threat_client.vt_api_key or threat_client.abuse_api_key else "Fallback / Demo Simulation Mode"
    }

frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
