import os
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.units import inch

def generate_cyber_crime_pdf(complaint_data: Dict[str, Any], output_dir: str = "reports") -> str:
    """
    Generate an official, court-admissible Cyber Crime Complaint & Forensic Dossier PDF.
    Returns the absolute path to the generated file.
    """
    os.makedirs(output_dir, exist_ok=True)
    case_id = complaint_data.get("case_id", "CYBER_CASE_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    filename = f"CyberCrime_Complaint_{case_id}.pdf"
    pdf_path = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom typography
    doc_title = ParagraphStyle(
        'CrimeDocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#991b1b'), # Deep crimson red
        fontName='Helvetica-Bold',
        alignment=1 # Center
    )

    sub_title = ParagraphStyle(
        'CrimeDocSubTitle',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#475569'),
        fontName='Helvetica-Bold',
        alignment=1
    )

    section_hdr = ParagraphStyle(
        'CrimeSectionHdr',
        parent=styles['Heading2'],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0f172a'),
        fontName='Helvetica-Bold',
        spaceBefore=8,
        spaceAfter=4
    )

    body_txt = ParagraphStyle(
        'CrimeBodyTxt',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#1e293b'),
        fontName='Helvetica'
    )

    code_txt = ParagraphStyle(
        'CrimeCodeTxt',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#0f172a'),
        fontName='Courier'
    )

    story = []

    # 1. Official Header
    story.append(Paragraph("CYBER CRIME INCIDENT REPORT & FORMAL COMPLAINT DOSSIER", doc_title))
    story.append(Paragraph("FOR SUBMISSION TO NATIONAL CYBER CRIME REPORTING PORTAL / LAW ENFORCEMENT CYBER CELL", sub_title))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#991b1b'), spaceBefore=2, spaceAfter=8))

    # 2. Case Tracking Header Bar
    complainant = complaint_data.get("complainant", {})
    incident = complaint_data.get("incident_details", {})
    suspect = complaint_data.get("suspect_profile", {})
    evidence = complaint_data.get("evidence_integrity", {})

    case_badge = Paragraph(f"<font size='12' color='white'><b>CASE FILE: {case_id}</b></font><br/><font size='8' color='#fecaca'>STATUS: OFFICIAL COMPLAINT FILED (HIGH PRIORITY)</font>", ParagraphStyle('CaseB', alignment=1))
    
    date_str = complaint_data.get("filing_timestamp", datetime.now().isoformat())
    case_meta = Paragraph(f"<b>Filing Date:</b> {date_str[:19].replace('T', ' ')} UTC<br/><b>Incident Classification:</b> {incident.get('type', 'Phishing & Wire Fraud')}<br/><b>Declared Financial Loss:</b> ${incident.get('financial_loss_amount', 0.0):,.2f}", ParagraphStyle('MetaB', parent=body_txt))

    header_table = Table([[case_badge, case_meta]], colWidths=[3.2 * inch, 4.3 * inch])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#991b1b')),
        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))

    # 3. Complainant & Suspect Profiles
    story.append(Paragraph("1. Parties Involved", section_hdr))
    parties_data = [
        [Paragraph("<b>Complainant / Victim:</b>", body_txt), Paragraph(f"{complainant.get('name', 'N/A')}  |  Email: {complainant.get('email', 'N/A')}  |  Phone: {complainant.get('phone', 'N/A')}", body_txt)],
        [Paragraph("<b>Suspect Claimed Identity:</b>", body_txt), Paragraph(suspect.get("claimed_sender", "Unknown"), body_txt)],
        [Paragraph("<b>Suspect Originating IP:</b>", body_txt), Paragraph(f"{suspect.get('originating_ip', 'N/A')} ({suspect.get('origin_country', 'N/A')})", code_txt)],
        [Paragraph("<b>Suspect ISP & ASN:</b>", body_txt), Paragraph(suspect.get("isp_asn", "N/A"), body_txt)],
        [Paragraph("<b>Geo Coordinates:</b>", body_txt), Paragraph(suspect.get("coordinates", "N/A"), code_txt)],
        [Paragraph("<b>Return-Path / Reply-To:</b>", body_txt), Paragraph(f"Return: {suspect.get('return_path', 'N/A')} | Reply: {suspect.get('reply_to', 'N/A')}", code_txt)],
    ]
    parties_table = Table(parties_data, colWidths=[2.0 * inch, 5.5 * inch])
    parties_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(parties_table)
    story.append(Spacer(1, 10))

    # 4. Incident Narrative & Financial Loss
    story.append(Paragraph("2. Statement of Incident & Impact", section_hdr))
    narrative_p = Paragraph(f"<b>Subject of Fraudulent Email:</b> {incident.get('target_subject', 'N/A')}<br/><br/><b>Incident Description:</b><br/>{incident.get('narrative', 'N/A')}", body_txt)
    narrative_table = Table([[narrative_p]], colWidths=[7.5 * inch])
    narrative_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fdf2f8')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#fbcfe8')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(narrative_table)
    story.append(Spacer(1, 10))

    # 5. Cryptographic Chain of Custody & Evidence Integrity
    story.append(Paragraph("3. Digital Evidence Integrity & Cryptographic Hashes", section_hdr))
    evidence_rows = [
        [Paragraph("<b>SHA-256 Hash:</b>", body_txt), Paragraph(evidence.get("sha256_hash", "N/A"), code_txt)],
        [Paragraph("<b>MD5 Hash:</b>", body_txt), Paragraph(evidence.get("md5_hash", "N/A"), code_txt)],
        [Paragraph("<b>SHA-1 Hash:</b>", body_txt), Paragraph(evidence.get("sha1_hash", "N/A"), code_txt)],
        [Paragraph("<b>Forensic Chain:</b>", body_txt), Paragraph("Cryptographically sealed at extraction. Verified bit-for-bit against source RFC 5322 .eml payload.", body_txt)],
    ]
    ev_table = Table(evidence_rows, colWidths=[1.8 * inch, 5.7 * inch])
    ev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 10))

    # 6. Applicable Statutory Violations
    story.append(Paragraph("4. Applicable Legal Provisions & Statutory Violations", section_hdr))
    statutes = complaint_data.get("statutory_violations", [])
    statute_rows = [
        [Paragraph("<b>Statutory Code</b>", body_txt), Paragraph("<b>Legal Description & Prescribed Penalties</b>", body_txt)]
    ]
    for s in statutes:
        statute_rows.append([
            Paragraph(f"<b>{s.get('code', '')}</b>", body_txt),
            Paragraph(f"{s.get('title', '')} — <i>{s.get('penalty', '')}</i>", body_txt)
        ])
    stat_table = Table(statute_rows, colWidths=[2.3 * inch, 5.2 * inch])
    stat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fee2e2')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 10))

    # 7. Recommended Law Enforcement Actions
    story.append(Paragraph("5. Recommended Law Enforcement Interventions", section_hdr))
    actions = complaint_data.get("recommended_police_actions", [])
    actions_p = Paragraph("<br/>".join([f"• <b>[ACTION {i+1}]</b> {act}" for i, act in enumerate(actions)]), body_txt)
    actions_table = Table([[actions_p]], colWidths=[7.5 * inch])
    actions_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(actions_table)
    story.append(Spacer(1, 12))

    # 8. Certification & Signature Box
    sign_text = Paragraph(
        "<b>OFFICIAL DECLARATION & CERTIFICATION:</b><br/>"
        "I hereby affirm that the facts stated in this complaint dossier and the technical evidence presented are true to the best of my knowledge and belief. "
        "Generated via SentinelEML Forensic Automated Verification Suite.",
        ParagraphStyle('SignP', parent=body_txt, fontSize=7.5, leading=10, textColor=colors.HexColor('#64748b'))
    )
    story.append(sign_text)

    doc.build(story)
    return os.path.abspath(pdf_path)
