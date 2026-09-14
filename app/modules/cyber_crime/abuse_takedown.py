from datetime import datetime, timezone
from typing import Dict, Any

def generate_abuse_takedown_notice(scan_data: Dict[str, Any], reporter_email: str = "security@yourdomain.com") -> Dict[str, Any]:
    """
    Generate an RFC-compliant ISP Abuse & Phishing Takedown Notice email draft.
    """
    headers = scan_data.get("parsed_headers", {}).get("headers", {})
    routing = scan_data.get("parsed_headers", {}).get("routing", {})
    geo = scan_data.get("geolocation", {})
    links = scan_data.get("extracted_links", {})
    risk = scan_data.get("risk_assessment", {})

    sender_ip = routing.get("originating_ip", geo.get("ip", "Unknown"))
    sender_domain = headers.get("from_domain", "Unknown")
    isp = geo.get("isp", "ISP Abuse Team")

    defanged_urls = [u.get("defanged_url") for u in links.get("urls", []) if u.get("is_suspicious")]

    abuse_subject = f"[URGENT TAKEDOWN REQUEST] Phishing / Malicious Infrastructure on {sender_ip} ({sender_domain})"
    
    abuse_body = f"""To: abuse@{sender_domain}, abuse-contacts@{isp.lower().replace(' ', '')}.com, abuse@arin.net
From: {reporter_email}
Date: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')}
Subject: {abuse_subject}
Importance: High
X-Reported-By: SentinelEML Incident Response System

Dear Abuse and Network Security Team,

We are writing to report active malicious activity originating from infrastructure hosted under your network / autonomous system:

================================================================================
INCIDENT FORENSIC DETAILS
================================================================================
• Suspect Originating IP : {sender_ip}
• Network / ASN / ISP    : {geo.get('isp', 'N/A')} ({geo.get('asn', 'N/A')})
• Registered Location    : {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}
• Sender Email / Domain  : {headers.get('from_address', 'N/A')} ({sender_domain})
• Header Subject         : {headers.get('subject', 'N/A')}
• Threat Assessment Score: {risk.get('score', 0)}/100 ({risk.get('threat_level', 'MALICIOUS')})
• Timestamp of Detection : {datetime.now(timezone.utc).isoformat()}Z

================================================================================
FRAUDULENT / PHISHING DESTINATIONS DETECTED
================================================================================
{chr(10).join(['• ' + u for u in defanged_urls]) if defanged_urls else '• Malicious spoofing and unauthorized email relay.'}

================================================================================
REQUESTED ACTIONS
================================================================================
1. Immediately suspend the offending account / virtual server hosting {sender_ip}.
2. Place a DNS hold or null-route on malicious hostnames associated with {sender_domain}.
3. Preserve all connection logs, subscriber registration information, and payment records for law enforcement subpoena under applicable preservation statutes.

Please confirm receipt of this notice and provide your internal incident tracking ticket number.

Sincerely,
Incident Response & Security Operations
SentinelEML Automated Incident Dispatch
"""

    return {
        "abuse_target_isp": isp,
        "suggested_abuse_emails": [f"abuse@{sender_domain}", f"abuse@{isp.lower().replace(' ', '')}.com"],
        "subject": abuse_subject,
        "email_body": abuse_body.strip()
    }
