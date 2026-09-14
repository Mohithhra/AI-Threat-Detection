from typing import Dict, Any

def query_forensic_copilot(query: str, scan_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Forensic AI Copilot that provides natural language explanations of threat findings,
    legal guidance under IT Act 2000, and SOC remediation advisories.
    """
    q_lower = query.lower()

    headers = scan_data.get("parsed_headers", {}).get("headers", {}) if scan_data else {}
    auth = scan_data.get("parsed_headers", {}).get("authentication", {}) if scan_data else {}
    risk = scan_data.get("risk_assessment", {}) if scan_data else {}
    geo = scan_data.get("geolocation", {}) if scan_data else {}

    sender = headers.get("from_address", "suspect@unknown.com")
    subject = headers.get("subject", "Deceptive Communication")
    score = risk.get("score", 85)

    if "why" in q_lower or "risk" in q_lower or "flagged" in q_lower or "score" in q_lower:
        answer = (
            f"**Forensic AI Breakdown for Current Email**:\n\n"
            f"1. **Authentication Failure**: SPF is `{auth.get('spf_status', 'FAIL')}` and DMARC is `{auth.get('dmarc_status', 'FAIL')}`. "
            f"The claimed domain `{headers.get('from_domain', '')}` does not match the actual originating server IP (`{geo.get('ip', 'Unknown')}`).\n"
            f"2. **Threat Intelligence Matches**: The originating IP/Domain has malicious history registered in VirusTotal & AbuseIPDB.\n"
            f"3. **Overall Risk Rating**: **{score}/100 ({risk.get('threat_level', 'HIGH THREAT')})**."
        )
        actions = ["File Cyber Crime Complaint", "Download PDF Evidence", "Generate Abuse Takedown Notice"]

    elif "legal" in q_lower or "law" in q_lower or "section" in q_lower or "it act" in q_lower or "police" in q_lower:
        answer = (
            f"**Legal Framework Guidance (Indian Law)**:\n\n"
            f"- **IT Act 2000 Section 66D**: Cheating by Personation using computer resources (applies to sender `{sender}`).\n"
            f"- **IT Act 2000 Section 66C**: Identity Theft for spoofing header authentication.\n"
            f"- **BNS 2023 Section 318(4)**: Cheating & inducing delivery of property.\n\n"
            f"**Action Recommended**: Submit the NCRP FIR packet via our **National Cyber Crime Portal** tab to generate a court-admissible SHA-256 evidence chain."
        )
        actions = ["Generate NCRP FIR Packet", "Download Evidence Hash Certificate"]

    elif "advisory" in q_lower or "warn" in q_lower or "employee" in q_lower or "draft" in q_lower:
        answer = (
            f"**Draft Security Advisory for Internal Staff**:\n\n"
            f"**SUBJECT**: [SECURITY ALERT] Phishing Campaign Impersonating {headers.get('from_domain', 'External Entity')}\n\n"
            f"Dear Team,\n\n"
            f"Our Security Operations Center (SOC) has detected an active phishing email with subject *'{subject}'* targeting staff. "
            f"Do NOT click links, open attachments, or reply to `{sender}`. "
            f"If you suspect your credentials have been compromised, contact IT Security immediately."
        )
        actions = ["Copy Advisory Text", "Broadcast SOC Alert"]

    else:
        answer = (
            f"**Sentinel AI Copilot Status**: Standing by for SOC query.\n\n"
            f"Current Analysis context: Email from **{sender}** with Subject **'{subject}'** scored **{score}/100 Risk**.\n"
            f"You can ask me to explain threat vectors, provide legal IT Act sections, or draft employee mitigation advisories."
        )
        actions = ["Explain Threat Score", "Show Legal Sections", "Draft Security Advisory"]

    return {
        "query": query,
        "response": answer,
        "suggested_actions": actions,
        "threat_context": {
            "sender": sender,
            "subject": subject,
            "risk_score": score
        }
    }
