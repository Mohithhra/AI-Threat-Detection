import re
from typing import Dict, Any, List

# Keyword & Pattern taxonomies for zero-shot social engineering intent classification
TACTIC_PATTERNS = {
    "CEO_FRAUD_BEC": {
        "name": "CEO Fraud / Business Email Compromise (BEC)",
        "keywords": [r"wire transfer", r"urgent payment", r"gift card", r"discreet", r"confidential request", r"are you available", r"ceo", r"executive", r"vendor payment", r"bank update"],
        "weight": 35,
        "description": "Attacker impersonates executive management requesting urgent funds transfer or sensitive information."
    },
    "CREDENTIAL_HARVESTING": {
        "name": "Credential Harvesting / Portal Spoofing",
        "keywords": [r"verify your account", r"password expires", r"log in to restore", r"security alert", r"mailbox full", r"update credentials", r"microsoft office 365", r"google workspace", r"mfa", r"authentication update", r"scan qr code", r"account suspension"],
        "weight": 40,
        "description": "Attacker uses fake authentication portals to harvest usernames, passwords, and 2FA tokens."
    },
    "SEXTORTION_BLACKMAIL": {
        "name": "Financial Extortion / Blackmail (Sextortion)",
        "keywords": [r"recorded you", r"compromised your camera", r"bitcoin wallet", r"pay within 48 hours", r"nude video", r"trojan virus", r"pegasus spyware"],
        "weight": 45,
        "description": "Extortion attempt threatening exposure of private material unless cryptocurrency is paid."
    },
    "PACKAGE_CUSTOMS_SCAM": {
        "name": "Delivery & Customs Phishing",
        "keywords": [r"package on hold", r"customs duty fee", r"dhl shipment", r"fedex tracking", r"unpaid fee", r"reschedule delivery", r"usps update"],
        "weight": 25,
        "description": "Deceptive notification requesting small payment or credentials to release a non-existent package."
    },
    "LEGAL_TAX_FRAUD": {
        "name": "Legal & Tax Compliance Fraud",
        "keywords": [r"income tax notice", r"court summons", r"legal action", r"law enforcement", r"penalty fee", r"gst audit", r"police department"],
        "weight": 30,
        "description": "Impersonation of legal or tax authorities demanding compliance to induce panic."
    }
}

PSYCHOLOGICAL_TRIGGERS = [
    {"id": "URGENCY", "name": "Artificial Urgency", "pattern": r"\b(immediately|within 24 hours|action required|urgent|account suspended|final notice|expires today)\b", "weight": 15},
    {"id": "FEAR_PANIC", "name": "Fear & Coercion", "pattern": r"\b(legal action|arrest|police|suspended|terminated|lawsuit|prosecution|compromised)\b", "weight": 20},
    {"id": "FINANCIAL_GREED", "name": "Financial Bait / Wire Request", "pattern": r"\b(transfer \$|gift cards|\$5,000|wire transfer|refund approved|invoice attached|payment pending)\b", "weight": 20},
    {"id": "AUTHORITY", "name": "False Authority Stance", "pattern": r"\b(executive office|ceo|cyber security team|it helpdesk|director|managing director)\b", "weight": 10},
    {"id": "SECRECY", "name": "Secrecy & Isolation", "pattern": r"\b(keep this confidential|do not discuss|discreetly|do not call|reply only to this email)\b", "weight": 15}
]

def classify_email_intent(subject: str, text_body: str, html_body: str) -> Dict[str, Any]:
    """
    Analyzes subject and body content to extract AI intent classification,
    psychological manipulation vectors, and threat taxonomy.
    """
    combined_content = f"{subject}\n{text_body}\n{html_body}".lower()
    
    detected_tactics = []
    total_tactic_weight = 0

    for tactic_key, data in TACTIC_PATTERNS.items():
        matches = []
        for kw in data["keywords"]:
            if re.search(kw, combined_content, re.IGNORECASE):
                matches.append(kw)
        if matches:
            score_contribution = min(data["weight"], len(matches) * 12)
            total_tactic_weight += score_contribution
            detected_tactics.append({
                "key": tactic_key,
                "name": data["name"],
                "description": data["description"],
                "matched_triggers": matches,
                "severity": "CRITICAL" if score_contribution > 30 else "HIGH"
            })

    detected_triggers = []
    total_trigger_weight = 0
    for trig in PSYCHOLOGICAL_TRIGGERS:
        found = re.findall(trig["pattern"], combined_content, re.IGNORECASE)
        if found:
            count = len(found)
            weight = min(trig["weight"], count * 10)
            total_trigger_weight += weight
            detected_triggers.append({
                "id": trig["id"],
                "name": trig["name"],
                "matched_terms": list(set(found))[:5],
                "weight": weight
            })

    primary_tactic = detected_tactics[0]["name"] if detected_tactics else "Low Threat / Informational Communication"
    ai_risk_score = min(100, total_tactic_weight + total_trigger_weight)

    # Generate Explainable AI Analyst Insight
    if detected_tactics:
        ai_summary = f"The email exhibits traits of **{primary_tactic}**. "
        if detected_triggers:
            trig_names = ", ".join([t["name"] for t in detected_triggers[:3]])
            ai_summary += f"The attacker utilizes psychological manipulation strategies involving **{trig_names}** to pressure the recipient."
        else:
            ai_summary += "Deceptive content patterns match known phishing vectors."
    else:
        ai_summary = "No prominent social engineering or psychological coercion patterns detected in email content."

    return {
        "primary_tactic": primary_tactic,
        "ai_risk_score": ai_risk_score,
        "detected_tactics": detected_tactics,
        "psychological_triggers": detected_triggers,
        "ai_summary": ai_summary,
        "recommended_action": "Isolate Email & File Cyber Complaint" if ai_risk_score > 60 else "Safe to Proceed / Standard Monitoring"
    }
