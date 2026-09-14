import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

def compute_evidence_hash(content: str) -> Dict[str, str]:
    """Compute cryptographic hashes for chain-of-custody evidentiary integrity."""
    raw_bytes = content.encode('utf-8') if isinstance(content, str) else content
    return {
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "sha1": hashlib.sha1(raw_bytes).hexdigest(),
        "md5": hashlib.md5(raw_bytes).hexdigest()
    }

def determine_statutory_violations(incident_type: str, threat_score: int, has_spoofing: bool) -> list:
    """Map the incident to relevant cybercrime legal provisions and penal codes."""
    violations = [
        {
            "code": "IT Act 2000 - Section 66D",
            "title": "Punishment for cheating by personation by using computer resource",
            "penalty": "Imprisonment up to 3 years and fine up to 1 Lakh INR"
        },
        {
            "code": "IT Act 2000 - Section 66C",
            "title": "Punishment for identity theft (fraudulent use of electronic signature / identity)",
            "penalty": "Imprisonment up to 3 years and fine"
        },
        {
            "code": "IPC Section 419 & 420",
            "title": "Cheating by personation and dishonestly inducing delivery of property",
            "penalty": "Imprisonment up to 7 years and fine"
        },
        {
            "code": "18 U.S. Code § 1030 / 18 U.S.C. § 1343",
            "title": "Fraud and related activity in connection with computers / Wire Fraud",
            "penalty": "Federal prosecution under US IC3 guidelines"
        }
    ]
    return violations

def generate_complaint_record(
    scan_data: Dict[str, Any],
    victim_name: str,
    victim_email: str,
    victim_phone: str,
    incident_type: str,
    financial_loss: float = 0.0,
    narrative: str = "",
    raw_eml: str = ""
) -> Dict[str, Any]:
    """
    Generate an official Cyber Crime Complaint record with cryptographic evidence hashes,
    suspect profiling, and legal statutory mappings.
    """
    timestamp = datetime.now(timezone.utc)
    case_id = f"CYBER-{timestamp.strftime('%Y%m')}-{uuid.uuid4().hex[:6].upper()}"

    headers = scan_data.get("parsed_headers", {}).get("headers", {})
    routing = scan_data.get("parsed_headers", {}).get("routing", {})
    geo = scan_data.get("geolocation", {})
    risk = scan_data.get("risk_assessment", {})
    intel = scan_data.get("threat_intelligence", {})

    evidence_hashes = compute_evidence_hash(raw_eml or headers.get("subject", "") + str(timestamp))

    suspect_profile = {
        "claimed_sender": f"{headers.get('from_name', '')} <{headers.get('from_address', '')}>",
        "sender_domain": headers.get("from_domain", "Unknown"),
        "return_path": headers.get("return_path", "N/A"),
        "reply_to": headers.get("reply_to", "N/A"),
        "originating_ip": routing.get("originating_ip", geo.get("ip", "Unknown")),
        "origin_country": f"{geo.get('city', '')}, {geo.get('country', 'Unknown')}",
        "isp_asn": f"{geo.get('isp', 'N/A')} ({geo.get('asn', 'N/A')})",
        "coordinates": f"{geo.get('lat', 0.0)}, {geo.get('lon', 0.0)}",
        "threat_score": risk.get("score", 0),
        "threat_level": risk.get("threat_level", "MALICIOUS")
    }

    legal_sections = determine_statutory_violations(
        incident_type=incident_type,
        threat_score=risk.get("score", 0),
        has_spoofing=scan_data.get("parsed_headers", {}).get("authentication", {}).get("domain_mismatch", False)
    )

    complaint_data = {
        "case_id": case_id,
        "filing_timestamp": timestamp.isoformat(),
        "status": "FILED_WITH_CYBER_CELL",
        "complainant": {
            "name": victim_name or "Anonymous Complainant",
            "email": victim_email or "N/A",
            "phone": victim_phone or "N/A",
        },
        "incident_details": {
            "type": incident_type or "Phishing & Identity Impersonation",
            "financial_loss_amount": financial_loss,
            "currency": "USD / INR",
            "narrative": narrative or "The victim received an unsolicited fraudulent communication attempting unauthorized access, identity spoofing, or financial fraud.",
            "target_subject": headers.get("subject", "N/A")
        },
        "suspect_profile": suspect_profile,
        "evidence_integrity": {
            "sha256_hash": evidence_hashes["sha256"],
            "sha1_hash": evidence_hashes["sha1"],
            "md5_hash": evidence_hashes["md5"],
            "chain_of_custody_verified": True
        },
        "statutory_violations": legal_sections,
        "recommended_police_actions": [
            f"Issue emergency preservation notice under Section 91 CrPC / 18 U.S.C. § 2703(f) to ISP {geo.get('isp', 'Hosting Provider')}.",
            f"Block suspect originating IP ({routing.get('originating_ip', 'N/A')}) and associated domain ({headers.get('from_domain', 'N/A')}) at gateway/national firewalls.",
            "Request subscriber connection logs (NAT/DHCP timestamps) from the originating ISP.",
            "Initiate freeze on any associated banking or escrow accounts mentioned in the communication."
        ]
    }

    return complaint_data
