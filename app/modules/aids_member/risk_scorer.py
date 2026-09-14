import re
from typing import Dict, Any, List

URGENCY_KEYWORDS = [
    r'\bimmediate(?:ly)? action required\b',
    r'\baccount (?:has been )?suspended\b',
    r'\bverify your (?:account|identity|password|credentials|wallet)\b',
    r'\bunauthorized (?:access|login|activity)\b',
    r'\bwire transfer\b',
    r'\bpayroll update\b',
    r'\bgift cards?\b',
    r'\boverdue invoice\b',
    r'\bsecurity alert: login attempt\b',
    r'\bconfirm your details\b',
    r'\bbitcoin|crypto(?:currency)?\b',
    r'\bclick here to unlock\b',
    r'\bfinal notice\b'
]

def check_urgency_and_phishing_language(subject: str, body_text: str) -> List[str]:
    """Scan subject and body for typical social engineering / urgency trigger phrases."""
    combined = f"{subject}\n{body_text}".lower()
    triggers_found = []
    
    for pattern in URGENCY_KEYWORDS:
        if re.search(pattern, combined, re.IGNORECASE):
            clean_phrase = pattern.replace(r'\b', '').replace('(?:', '').replace(')?', '').replace('|', ' / ')
            triggers_found.append(clean_phrase)
            
    return triggers_found

def evaluate_email_risk(
    header_data: Dict[str, Any],
    threat_intel_data: Dict[str, Any],
    link_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Compute an explainable, deterministic 0-100 risk score based on transparent weighted signals.
    """
    signals: List[Dict[str, Any]] = []
    total_score = 0

    auth = header_data.get("authentication", {})
    headers = header_data.get("headers", {})
    body = header_data.get("body", {})
    
    # -------------------------------------------------------------
    # 1. AUTHENTICATION SIGNALS (SPF, DKIM, DMARC)
    # -------------------------------------------------------------
    spf_status = auth.get("spf_status", "none").lower()
    if spf_status == "fail":
        weight = 30
        total_score += weight
        signals.append({
            "id": "AUTH_SPF_FAIL",
            "category": "AUTHENTICATION",
            "name": "SPF Authentication Failed",
            "weight": weight,
            "severity": "HIGH",
            "description": "The sending server IP is NOT authorized to send emails on behalf of this domain."
        })
    elif spf_status == "softfail":
        weight = 15
        total_score += weight
        signals.append({
            "id": "AUTH_SPF_SOFTFAIL",
            "category": "AUTHENTICATION",
            "name": "SPF Authentication Softfail",
            "weight": weight,
            "severity": "MEDIUM",
            "description": "The sending domain discourages this host from sending mail (~all policy)."
        })

    dkim_status = auth.get("dkim_status", "none").lower()
    if dkim_status == "fail":
        weight = 25
        total_score += weight
        signals.append({
            "id": "AUTH_DKIM_FAIL",
            "category": "AUTHENTICATION",
            "name": "DKIM Cryptographic Signature Invalid",
            "weight": weight,
            "severity": "HIGH",
            "description": "DKIM signature check failed; email body or headers may have been modified in transit."
        })

    dmarc_status = auth.get("dmarc_status", "none").lower()
    if dmarc_status == "fail":
        weight = 30
        total_score += weight
        signals.append({
            "id": "AUTH_DMARC_FAIL",
            "category": "AUTHENTICATION",
            "name": "DMARC Policy Alignment Failed",
            "weight": weight,
            "severity": "CRITICAL",
            "description": "Email failed DMARC validation against the sender domain's published security policy."
        })

    # -------------------------------------------------------------
    # 2. SENDER SPOOFING & DOMAIN ALIGNMENT SIGNALS
    # -------------------------------------------------------------
    if auth.get("domain_mismatch", False):
        weight = 25
        total_score += weight
        signals.append({
            "id": "SPOOF_DOMAIN_MISMATCH",
            "category": "SPOOFING",
            "name": "Header Domain Mismatch (From vs Return-Path/Reply-To)",
            "weight": weight,
            "severity": "HIGH",
            "description": "; ".join(auth.get("mismatch_details", ["Sender domain does not match return path."]))
        })

    # Check for Display Name Spoofing (e.g. Name is 'PayPal Support' but domain is 'gmail.com')
    from_name = headers.get("from_name", "").lower()
    from_domain = headers.get("from_domain", "").lower()
    high_target_brands = ["paypal", "microsoft", "google", "apple", "amazon", "chase", "bank of america", "wells fargo", "netflix", "fedex", "dhl", "irs", "docu sign"]
    for brand in high_target_brands:
        if brand in from_name and brand not in from_domain:
            weight = 30
            total_score += weight
            signals.append({
                "id": "SPOOF_DISPLAY_NAME",
                "category": "SPOOFING",
                "name": "Executive / Brand Display Name Spoofing",
                "weight": weight,
                "severity": "CRITICAL",
                "description": f"Sender display name masquerades as '{brand.title()}' while sending from an unrelated domain '{from_domain}'."
            })
            break

    # -------------------------------------------------------------
    # 3. THREAT INTELLIGENCE SIGNALS (AbuseIPDB + VirusTotal)
    # -------------------------------------------------------------
    ip_intel = threat_intel_data.get("ip_intelligence", {})
    abuse_score = ip_intel.get("abuse_confidence_score", 0)
    if abuse_score >= 50:
        weight = 35
        total_score += weight
        signals.append({
            "id": "INTEL_ABUSEIPDB_HIGH",
            "category": "THREAT_INTEL",
            "name": f"High IP Abuse Score ({abuse_score}%) on AbuseIPDB",
            "weight": weight,
            "severity": "CRITICAL",
            "description": f"The originating IP ({ip_intel.get('ip')}) has {ip_intel.get('total_reports', 0)} recorded abuse reports for spam/malware/attacks."
        })
    elif abuse_score >= 20:
        weight = 20
        total_score += weight
        signals.append({
            "id": "INTEL_ABUSEIPDB_MED",
            "category": "THREAT_INTEL",
            "name": f"Moderate IP Abuse Score ({abuse_score}%) on AbuseIPDB",
            "weight": weight,
            "severity": "MEDIUM",
            "description": f"Originating IP ({ip_intel.get('ip')}) has historical abuse reports."
        })

    # VirusTotal domain / URL flags
    domain_intel = threat_intel_data.get("domain_intelligence", {})
    if domain_intel.get("malicious_count", 0) > 0:
        weight = 40
        total_score += weight
        signals.append({
            "id": "INTEL_VT_MALICIOUS_DOMAIN",
            "category": "THREAT_INTEL",
            "name": f"Sender Domain Flagged Malicious on VirusTotal ({domain_intel.get('malicious_count')} engines)",
            "weight": weight,
            "severity": "CRITICAL",
            "description": f"Domain '{domain_intel.get('target')}' is identified as malicious by security vendors."
        })

    url_intel_list = threat_intel_data.get("url_intelligence", [])
    malicious_urls = [u for u in url_intel_list if u.get("malicious_count", 0) > 0]
    if malicious_urls:
        weight = 40
        total_score += weight
        signals.append({
            "id": "INTEL_VT_MALICIOUS_URL",
            "category": "THREAT_INTEL",
            "name": f"Embedded Link Flagged Malicious ({len(malicious_urls)} URLs)",
            "weight": weight,
            "severity": "CRITICAL",
            "description": f"VirusTotal engines detected known malicious / phishing links in the email body."
        })

    # -------------------------------------------------------------
    # 4. CONTENT & URL ANOMALY SIGNALS
    # -------------------------------------------------------------
    raw_urls = link_data.get("urls", [])
    has_ip_url = any("Raw IP address used as URL host" in flag for u in raw_urls for flag in u.get("flags", []))
    if has_ip_url:
        weight = 20
        total_score += weight
        signals.append({
            "id": "CONTENT_RAW_IP_URL",
            "category": "CONTENT_ANALYSIS",
            "name": "Raw IP Address Used in Hyperlink",
            "weight": weight,
            "severity": "HIGH",
            "description": "Hyperlink points directly to an IP address instead of a legitimate registered domain name."
        })

    has_mismatched_anchor = any("Mismatched anchor text" in flag for u in raw_urls for flag in u.get("flags", []))
    if has_mismatched_anchor:
        weight = 25
        total_score += weight
        signals.append({
            "id": "CONTENT_MISMATCHED_ANCHOR",
            "category": "CONTENT_ANALYSIS",
            "name": "Deceptive Hyperlink Anchor Text",
            "weight": weight,
            "severity": "HIGH",
            "description": "Visual anchor text shows one URL while the underlying hyperlink directs the user to a completely different domain."
        })

    has_shortener = any("URL shortener used" in flag for u in raw_urls for flag in u.get("flags", []))
    if has_shortener:
        weight = 10
        total_score += weight
        signals.append({
            "id": "CONTENT_URL_SHORTENER",
            "category": "CONTENT_ANALYSIS",
            "name": "URL Shortener Detected in Body",
            "weight": weight,
            "severity": "LOW",
            "description": "Shortened links are frequently utilized in phishing to hide landing page destinations."
        })

    # Urgency & Phishing Language
    urgency_phrases = check_urgency_and_phishing_language(headers.get("subject", ""), body.get("text", ""))
    if urgency_phrases:
        weight = 15
        total_score += weight
        signals.append({
            "id": "CONTENT_URGENCY_LANGUAGE",
            "category": "CONTENT_ANALYSIS",
            "name": "Social Engineering & Urgency Indicators Detected",
            "weight": weight,
            "severity": "MEDIUM",
            "description": f"Trigger phrases detected: {', '.join(urgency_phrases[:3])}"
        })

    # -------------------------------------------------------------
    # FINAL SCORE NORMALIZATION & VERDICT
    # -------------------------------------------------------------
    clamped_score = min(100, max(0, total_score))

    if clamped_score >= 70:
        threat_level = "MALICIOUS"
        color = "#ef4444" # Tailwind Red
        summary = "CRITICAL THREAT: This email exhibits multiple high-confidence indicators of phishing, domain spoofing, or malware delivery. Do not open attachments or click links."
    elif clamped_score >= 30:
        threat_level = "SUSPICIOUS"
        color = "#f59e0b" # Tailwind Amber
        summary = "SUSPICIOUS: Several anomalies or unverified authentication headers were identified. Exercise extreme caution."
    else:
        threat_level = "CLEAN"
        color = "#10b981" # Tailwind Emerald
        summary = "CLEAN: No significant threat indicators detected. SPF/DKIM/DMARC protocols appear aligned and threat reputation is benign."

    return {
        "score": clamped_score,
        "raw_score": total_score,
        "threat_level": threat_level,
        "color": color,
        "summary": summary,
        "signals_count": len(signals),
        "signals": signals
    }
