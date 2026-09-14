import os
import smtplib
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Dict, Any, List

# Official State Cyber Crime Helpline Email Directory (India & International Law Enforcement)
CYBER_CELL_EMAIL_DIRECTORY = {
    "NATIONAL_NCRP": "complaint@cybercrime.gov.in",
    "DELHI_CYBER": "cybercell-delhi@nic.in",
    "MUMBAI_CYBER": "cybercell.mumbai@mahapolice.gov.in",
    "BANGALORE_CYBER": "cybercrimeps@ksp.gov.in",
    "TAMILNADU_CYBER": "cyber-cbi@cbi.gov.in",
    "HYDERABAD_CYBER": "cybercrime-hyd@tspolice.gov.in"
}

def generate_firewall_block_command(ip: str, domain: str) -> Dict[str, Any]:
    """
    Generates system firewall and mail filter commands to block malicious IP and domain.
    """
    windows_cmd = f'netsh advfirewall firewall add rule name="Block_Threat_{ip}" dir=in action=block remoteip={ip}'
    linux_iptables = f'iptables -A INPUT -s {ip} -j DROP'
    postfix_rule = f'{domain} REJECT Malicious Phishing Domain Blocked by SentinelEML'

    return {
        "target_ip": ip,
        "target_domain": domain,
        "windows_firewall_cmd": windows_cmd,
        "linux_iptables_cmd": linux_iptables,
        "postfix_block_rule": postfix_rule,
        "hosts_file_entry": f"127.0.0.1 {domain}"
    }

def apply_local_ip_block(ip: str) -> Dict[str, Any]:
    """
    Executes firewall block rule on local host operating system.
    """
    try:
        if os.name == 'nt': # Windows
            cmd = f'netsh advfirewall firewall add rule name="SentinelEML_Block_{ip}" dir=in action=block remoteip={ip}'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            success = res.returncode == 0
            message = res.stdout if success else res.stderr
        else: # Linux / Mac
            cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            success = res.returncode == 0
            message = res.stdout if success else res.stderr
            
        return {
            "success": success,
            "ip": ip,
            "message": message or f"Firewall rule applied to block {ip}"
        }
    except Exception as e:
        return {
            "success": False,
            "ip": ip,
            "error": str(e)
        }

def dispatch_real_cyber_crime_email(
    complaint_data: Dict[str, Any],
    pdf_path: str,
    target_cyber_cell: str = "NATIONAL_NCRP",
    smtp_server: str = "smtp.gmail.com",
    smtp_port: int = 587,
    sender_email: str = "",
    sender_password: str = ""
) -> Dict[str, Any]:
    """
    Dispatches formal legal FIR complaint packet to official State Cyber Crime Cell email endpoint with PDF dossier attached.
    """
    dest_email = CYBER_CELL_EMAIL_DIRECTORY.get(target_cyber_cell, "complaint@cybercrime.gov.in")
    case_id = complaint_data.get("case_id", "NCRP-2026-UNKNOWN")
    suspect_ip = complaint_data.get("suspect_profile", {}).get("originating_ip", "127.0.0.1")
    suspect_email = complaint_data.get("suspect_profile", {}).get("claimed_sender", "suspect@phish.com")

    subject = f"[OFFICIAL CYBER COMPLAINT] {case_id} - Phishing & Extortion Incident Report (IP: {suspect_ip})"

    body = f"""OFFICIAL CYBER CRIME INCIDENT COMPLAINT & EVIDENTIARY SUBMISSION

Case Reference ID: {case_id}
Date/Time of Incident: {complaint_data.get('created_at', '')}

TO THE OFFICER IN CHARGE, CYBER CRIME CELL / NCRP PORTAL:

This is an official cyber crime incident report filed via SentinelEML Threat Intelligence Platform.

COMPLAINANT DETAILS:
Name: {complaint_data.get('victim_details', {}).get('name', 'Victim')}
Email: {complaint_data.get('victim_details', {}).get('email', 'victim@email.com')}
Phone: {complaint_data.get('victim_details', {}).get('phone', 'N/A')}

SUSPECT TELEMETRY:
Sender Email Address: {suspect_email}
Originating IP Address: {suspect_ip}
Origin Location: {complaint_data.get('suspect_profile', {}).get('origin_country', 'Unknown')}
Financial Loss Declared: ₹{complaint_data.get('financial_loss', 0.0)}

STATUTORY APPLICABLE LAWS:
- IT Act 2000 Section 66D (Cheating by Personation)
- IT Act 2000 Section 66C (Identity Theft & Email Header Spoofing)
- BNS 2023 Section 318(4) / IPC 420 (Financial Fraud)

DIGITAL EVIDENCE INTEGRITY:
Evidence SHA-256 Hash Stamp: {complaint_data.get('evidence_integrity', {}).get('sha256_hash', 'N/A')}

Attached to this email is the official court-admissible Cyber Crime Complaint PDF Dossier.

Respectfully submitted,
SentinelEML Automated Cyber Crime Escalation System
"""

    if not sender_email or not sender_password:
        return {
            "status": "DISPATCH_READY_SIMULATED",
            "case_id": case_id,
            "destination_cyber_cell": dest_email,
            "subject": subject,
            "message": "Complaint packet formatted and ready for submission to Cyber Cell. Provide SMTP credentials to execute live email transmission.",
            "email_body_preview": body
        }

    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = dest_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        if pdf_path and os.path.exists(pdf_path):
            with open(pdf_path, 'rb') as f:
                pdf_attachment = MIMEApplication(f.read(), _subtype="pdf")
                pdf_attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(pdf_path))
                msg.attach(pdf_attachment)

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()

        return {
            "status": "DISPATCHED_TO_CYBER_CELL",
            "case_id": case_id,
            "destination": dest_email,
            "message": f"Successfully transmitted legal complaint to {dest_email}"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "error": str(e)
        }
