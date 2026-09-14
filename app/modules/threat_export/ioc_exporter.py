import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

def generate_stix_bundle(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate an industry-standard STIX 2.1 JSON Cyber Threat Intelligence bundle."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"

    headers = scan_data.get("parsed_headers", {}).get("headers", {})
    routing = scan_data.get("parsed_headers", {}).get("routing", {})
    links = scan_data.get("extracted_links", {})
    attachments = scan_data.get("attachments", {}).get("attachments", [])
    risk = scan_data.get("risk_assessment", {})

    objects = []

    # 1. Identity Object
    identity_id = f"identity--{uuid.uuid4()}"
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": timestamp,
        "modified": timestamp,
        "name": "SentinelEML Automated SOC Threat Engine",
        "identity_class": "system"
    })

    # 2. Indicator for Sender IP
    sender_ip = routing.get("originating_ip")
    if sender_ip and sender_ip != "127.0.0.1":
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": f"Malicious Originating Mail Host: {sender_ip}",
            "description": f"Email threat indicator with risk score {risk.get('score', 0)}/100",
            "pattern": f"[ipv4-addr:value = '{sender_ip}']",
            "pattern_type": "stix",
            "valid_from": timestamp,
            "confidence": min(100, risk.get("score", 75))
        })

    # 3. Indicator for Sender Domain
    sender_domain = headers.get("from_domain")
    if sender_domain:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": f"Spoofed/Phishing Domain: {sender_domain}",
            "pattern": f"[domain-name:value = '{sender_domain}']",
            "pattern_type": "stix",
            "valid_from": timestamp,
            "confidence": min(100, risk.get("score", 75))
        })

    # 4. Indicators for Extracted Malicious URLs
    for url_obj in links.get("urls", []):
        if url_obj.get("is_suspicious") or risk.get("score", 0) >= 50:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"Phishing URL: {url_obj.get('defanged_url')}",
                "pattern": f"[url:value = '{url_obj.get('url')}']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "confidence": 90
            })

    # 5. Indicators for Attachment Hashes
    for att in attachments:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": f"Malicious Email Attachment Hash: {att.get('filename')}",
            "pattern": f"[file:hashes.'SHA-256' = '{att.get('sha256')}']",
            "pattern_type": "stix",
            "valid_from": timestamp,
            "confidence": 95 if att.get("is_dangerous") else 60
        })

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }

def generate_csv_iocs(scan_data: Dict[str, Any]) -> str:
    """Generate CSV format Indicators of Compromise for firewall/SIEM bulk import."""
    headers = scan_data.get("parsed_headers", {}).get("headers", {})
    routing = scan_data.get("parsed_headers", {}).get("routing", {})
    links = scan_data.get("extracted_links", {})
    attachments = scan_data.get("attachments", {}).get("attachments", [])
    risk = scan_data.get("risk_assessment", {})
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = ["IOC_Type,Indicator_Value,Threat_Severity,Source_Context,First_Seen"]

    # IP
    sender_ip = routing.get("originating_ip")
    if sender_ip and sender_ip != "127.0.0.1":
        lines.append(f"IPv4,{sender_ip},{risk.get('threat_level', 'MALICIOUS')},Originating Email Host,{timestamp}")

    # Domain
    domain = headers.get("from_domain")
    if domain:
        lines.append(f"Domain,{domain},{risk.get('threat_level', 'MALICIOUS')},Sender Domain,{timestamp}")

    # URLs
    for u in links.get("urls", []):
        lines.append(f"URL,\"{u.get('url')}\",{risk.get('threat_level', 'MALICIOUS')},Hyperlink Destination,{timestamp}")

    # File Hashes
    for att in attachments:
        lines.append(f"File_SHA256,{att.get('sha256')},{'HIGH' if att.get('is_dangerous') else 'MEDIUM'},Attachment: {att.get('filename')},{timestamp}")
        lines.append(f"File_MD5,{att.get('md5')},{'HIGH' if att.get('is_dangerous') else 'MEDIUM'},Attachment: {att.get('filename')},{timestamp}")

    return "\n".join(lines)

def generate_yara_snort_rules(scan_data: Dict[str, Any]) -> Dict[str, str]:
    """Generate YARA detection rule and Snort network IDS signature."""
    headers = scan_data.get("parsed_headers", {}).get("headers", {})
    routing = scan_data.get("parsed_headers", {}).get("routing", {})
    scan_id = scan_data.get("scan_id", "scan_default")
    sender_domain = headers.get("from_domain", "phishing-sample.com")
    sender_ip = routing.get("originating_ip", "1.2.3.4")

    # Snort Rule
    snort_rule = f'alert tcp $EXTERNAL_NET any -> $HOME_NET [25,587] (msg:"SENTINEL-EML Phishing Relay Detected from {sender_domain}"; content:"From: "; nocase; content:"@{sender_domain}"; nocase; sid:100000{scan_id[-4:] if len(scan_id)>=4 else "1234"}; rev:1; classtype:trojan-activity;)'

    # YARA Rule
    clean_rule_name = "Rule_SentinelEML_" + "".join(c for c in scan_id if c.isalnum())
    yara_rule = f"""rule {clean_rule_name}
{{
    meta:
        description = "Detects phishing payload from {sender_domain}"
        author = "SentinelEML SOC Auto-Generator"
        date = "{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        threat_level = "High"
    strings:
        $header_sender = "@{sender_domain}" nocase
        $subject_kw = "{headers.get('subject', 'Action Required')[:30]}" nocase
    condition:
        all of them
}}"""

    return {
        "snort_rule": snort_rule,
        "yara_rule": yara_rule
    }
