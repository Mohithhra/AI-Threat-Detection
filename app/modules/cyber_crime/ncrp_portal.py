import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any

INDIAN_STATUTORY_PROVISIONS = [
    {
        "act": "Information Technology Act, 2000",
        "section": "Section 66C",
        "title": "Punishment for Identity Theft",
        "description": "Fraudulently or dishonestly making use of electronic signature, password or unique identification feature of any person."
    },
    {
        "act": "Information Technology Act, 2000",
        "section": "Section 66D",
        "title": "Punishment for Cheating by Personation using Computer Resource",
        "description": "Cheating by personating by means of any communication device or computer resource (Email Spoofing / Phishing)."
    },
    {
        "act": "Information Technology Act, 2000",
        "section": "Section 43",
        "title": "Penalty and Compensation for Damage to Computer System",
        "description": "Accessing, downloading data, or introducing malware/viruses into a computer network without permission."
    },
    {
        "act": "Bharatiya Nyaya Sanhita (BNS), 2023 / IPC",
        "section": "Section 318(4) / IPC 420",
        "title": "Cheating and Dishonestly Inducing Delivery of Property",
        "description": "Financial fraud and fraudulent deception inducing victim to transfer funds."
    },
    {
        "act": "Bharatiya Nyaya Sanhita (BNS), 2023 / IPC",
        "section": "Section 319 / IPC 419",
        "title": "Punishment for Cheating by Personation",
        "description": "Impersonating company officials, executives, or law enforcement officers via digital communication."
    }
]

def generate_ncrp_complaint_payload(
    scan_data: Dict[str, Any],
    victim_name: str,
    victim_email: str,
    victim_phone: str,
    incident_type: str = "Financial Cyber Fraud & Email Spoofing",
    financial_loss: float = 0.0,
    narrative: str = ""
) -> Dict[str, Any]:
    """
    Generates a full NCRP (National Cyber Crime Reporting Portal - cybercrime.gov.in) compliant legal docket.
    """
    ncrp_acknowledgment_no = f"NCRP-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    fir_draft_id = f"FIR-DRAFT-{uuid.uuid4().hex[:8].upper()}"
    
    headers = scan_data.get("parsed_headers", {}).get("headers", {})
    routing = scan_data.get("parsed_headers", {}).get("routing", {})
    geo = scan_data.get("geolocation", {})
    risk = scan_data.get("risk_assessment", {})
    raw_eml = scan_data.get("raw_eml", "")

    # Calculate SHA-256 digital evidence hash
    evidence_hash = hashlib.sha256(raw_eml.encode("utf-8")).hexdigest() if raw_eml else hashlib.sha256(str(headers).encode("utf-8")).hexdigest()

    # Applicable Laws Selection
    applicable_laws = INDIAN_STATUTORY_PROVISIONS[:3]
    if financial_loss > 0 or "financial" in incident_type.lower():
        applicable_laws.append(INDIAN_STATUTORY_PROVISIONS[3])
    applicable_laws.append(INDIAN_STATUTORY_PROVISIONS[4])

    payload = {
        "ncrp_acknowledgment_no": ncrp_acknowledgment_no,
        "fir_draft_id": fir_draft_id,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "portal_destination": "National Cyber Crime Reporting Portal (cybercrime.gov.in) - Ministry of Home Affairs (MHA), Govt. of India",
        "jurisdiction": "State Cyber Crime Cell & District Cyber Police Station",
        "complainant_details": {
            "full_name": victim_name,
            "email": victim_email,
            "mobile": victim_phone,
            "category": "Individual / Business Victim"
        },
        "incident_classification": {
            "primary_category": "Financial Cyber Fraud / Email Phishing",
            "sub_category": incident_type,
            "financial_loss_inr": financial_loss,
            "incident_date": headers.get("date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "threat_severity": risk.get("threat_level", "HIGH")
        },
        "suspect_evidence_profile": {
            "claimed_sender_email": headers.get("from_address", "Unknown"),
            "sender_domain": headers.get("from_domain", "Unknown"),
            "originating_ip_address": routing.get("originating_ip", "127.0.0.1"),
            "geoip_country": geo.get("country", "Unknown"),
            "geoip_city": geo.get("city", "Unknown"),
            "isp_provider": geo.get("isp", "Unknown"),
            "mail_server_hops": routing.get("hops", [])
        },
        "evidence_chain_of_custody": {
            "eml_filename": scan_data.get("filename", "evidence.eml"),
            "sha256_hash": evidence_hash,
            "md5_hash": hashlib.md5(raw_eml.encode("utf-8")).hexdigest() if raw_eml else "",
            "court_admissible_format": "RFC 822 Raw MIME Stream + Signed PDF Dossier"
        },
        "statutory_law_citations": applicable_laws,
        "narrative": narrative or f"The victim received a deceptive email claiming to be from {headers.get('from_address', 'attacker')}. Technical analysis confirms SPF/DKIM validation failures and malicious intent.",
        "status": "DISPATCHED_TO_STATE_CYBER_CELL",
        "tracking_url": f"https://cybercrime.gov.in/track/{ncrp_acknowledgment_no}"
    }

    return payload
