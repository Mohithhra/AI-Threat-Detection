import os
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.units import inch

def generate_pdf_report(scan_data: Dict[str, Any], output_dir: str = "reports") -> str:
    """
    Generate an executive PDF forensic threat analysis report.
    Returns the absolute path to the generated PDF.
    """
    os.makedirs(output_dir, exist_ok=True)
    scan_id = scan_data.get("scan_id", "scan_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    filename = f"Threat_Report_{scan_id}.pdf"
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

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b'),
        fontName='Helvetica'
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1e293b'),
        fontName='Helvetica-Bold',
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155'),
        fontName='Helvetica'
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0f172a'),
        fontName='Courier'
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("EMAIL THREAT INTELLIGENCE & FORENSIC REPORT", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  |  Scan ID: {scan_id}  |  File: {scan_data.get('filename', 'email.eml')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceBefore=2, spaceAfter=12))

    # 2. Executive Risk Summary Box
    risk = scan_data.get("risk_assessment", {})
    score = risk.get("score", 0)
    level = risk.get("threat_level", "CLEAN")
    summary_text = risk.get("summary", "")

    badge_bg = colors.HexColor('#10b981') if level == "CLEAN" else (colors.HexColor('#f59e0b') if level == "SUSPICIOUS" else colors.HexColor('#ef4444'))
    
    score_p = Paragraph(f"<font size='22' color='white'><b>{score}/100</b></font><br/><font size='11' color='white'><b>{level}</b></font>", ParagraphStyle('ScoreP', alignment=1))
    summary_p = Paragraph(f"<b>Executive Summary:</b><br/>{summary_text}", ParagraphStyle('SumP', parent=body_style, textColor=colors.HexColor('#0f172a')))

    summary_table = Table(
        [[score_p, summary_p]],
        colWidths=[1.8 * inch, 5.7 * inch]
    )
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), badge_bg),
        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('ALIGN', (0, 0), (0, 0), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 3. Email Metadata & Routing
    story.append(Paragraph("1. Header & Identity Metadata", section_heading))
    headers = scan_data.get("parsed_headers", {}).get("headers", {})
    routing = scan_data.get("parsed_headers", {}).get("routing", {})

    meta_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(headers.get("subject", "N/A"), body_style)],
        [Paragraph("<b>From:</b>", body_style), Paragraph(f"{headers.get('from_name', '')} &lt;{headers.get('from_address', 'N/A')}&gt;", body_style)],
        [Paragraph("<b>To:</b>", body_style), Paragraph(headers.get("to_address", "N/A"), body_style)],
        [Paragraph("<b>Date:</b>", body_style), Paragraph(headers.get("date", "N/A"), body_style)],
        [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(headers.get("return_path", "N/A"), body_style)],
        [Paragraph("<b>Originating IP:</b>", body_style), Paragraph(routing.get("originating_ip", "N/A"), code_style)],
        [Paragraph("<b>Total Relay Hops:</b>", body_style), Paragraph(str(routing.get("total_hops", 0)), body_style)],
    ]

    meta_table = Table(meta_data, colWidths=[1.6 * inch, 5.9 * inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 4. Email Authentication Matrix (SPF / DKIM / DMARC)
    story.append(Paragraph("2. Email Authentication Matrix", section_heading))
    auth = scan_data.get("parsed_headers", {}).get("authentication", {})
    dns_v = auth.get("dns_verification", {})

    def make_status_badge(status_str: str) -> str:
        s = (status_str or "none").lower()
        if "pass" in s:
            return "<font color='#16a34a'><b>PASS</b></font>"
        elif "fail" in s or "reject" in s:
            return "<font color='#dc2626'><b>FAIL</b></font>"
        elif "softfail" in s or "quarantine" in s:
            return "<font color='#d97706'><b>SOFTFAIL / QUARANTINE</b></font>"
        return f"<font color='#64748b'><b>{s.upper()}</b></font>"

    auth_rows = [
        [
            Paragraph("<b>Protocol</b>", body_style),
            Paragraph("<b>Header Result</b>", body_style),
            Paragraph("<b>DNS Record Discovered</b>", body_style)
        ],
        [
            Paragraph("<b>SPF (Sender Policy Framework)</b>", body_style),
            Paragraph(make_status_badge(auth.get("spf_status", "none")), body_style),
            Paragraph(dns_v.get("spf_record") or "No published SPF TXT record", code_style)
        ],
        [
            Paragraph("<b>DKIM (DomainKeys Identified Mail)</b>", body_style),
            Paragraph(make_status_badge(auth.get("dkim_status", "none")), body_style),
            Paragraph("DKIM Signature Header Attached" if auth.get("has_dkim_signature") else "No DKIM signature found", body_style)
        ],
        [
            Paragraph("<b>DMARC (Domain-based Auth)</b>", body_style),
            Paragraph(make_status_badge(auth.get("dmarc_status", "none")), body_style),
            Paragraph(dns_v.get("dmarc_record") or "No published DMARC record (_dmarc)", code_style)
        ]
    ]

    auth_table = Table(auth_rows, colWidths=[2.2 * inch, 1.8 * inch, 3.5 * inch])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 14))

    # 5. Triggered Threat Indicators
    story.append(Paragraph("3. Explainable Risk Signals Triggered", section_heading))
    signals = risk.get("signals", [])
    
    if not signals:
        story.append(Paragraph("<i>No suspicious indicators were triggered for this email.</i>", body_style))
    else:
        sig_rows = [
            [
                Paragraph("<b>Signal Name</b>", body_style),
                Paragraph("<b>Category</b>", body_style),
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Weight</b>", body_style),
                Paragraph("<b>Description</b>", body_style)
            ]
        ]
        for s in signals:
            sev_color = "#dc2626" if s.get("severity") in ("CRITICAL", "HIGH") else ("#d97706" if s.get("severity") == "MEDIUM" else "#2563eb")
            sig_rows.append([
                Paragraph(f"<b>{s.get('name', '')}</b>", body_style),
                Paragraph(s.get("category", ""), body_style),
                Paragraph(f"<font color='{sev_color}'><b>{s.get('severity', '')}</b></font>", body_style),
                Paragraph(f"+{s.get('weight', 0)}", body_style),
                Paragraph(s.get("description", ""), body_style),
            ])

        sig_table = Table(sig_rows, colWidths=[2.0 * inch, 1.2 * inch, 0.9 * inch, 0.6 * inch, 2.8 * inch])
        sig_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fee2e2')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(sig_table)

    story.append(Spacer(1, 14))

    # 6. Threat Intel & Origin Geolocation
    story.append(Paragraph("4. Threat Intelligence & IP Geolocation", section_heading))
    intel = scan_data.get("threat_intelligence", {})
    geo = scan_data.get("geolocation", {})
    ip_intel = intel.get("ip_intelligence", {})
    dom_intel = intel.get("domain_intelligence", {})

    intel_geo_rows = [
        [Paragraph("<b>Origin Location:</b>", body_style), Paragraph(f"{geo.get('city', 'N/A')}, {geo.get('region', '')}, {geo.get('country', 'N/A')} ({geo.get('country_code', '')})", body_style)],
        [Paragraph("<b>ISP / Autonomous System:</b>", body_style), Paragraph(f"{geo.get('isp', 'N/A')} ({geo.get('asn', 'N/A')})", body_style)],
        [Paragraph("<b>Coordinates (Lat, Lon):</b>", body_style), Paragraph(f"{geo.get('lat', 0.0)}, {geo.get('lon', 0.0)}", body_style)],
        [Paragraph("<b>AbuseIPDB Confidence:</b>", body_style), Paragraph(f"{ip_intel.get('abuse_confidence_score', 0)}% (Reports: {ip_intel.get('total_reports', 0)})", body_style)],
        [Paragraph("<b>VirusTotal Domain Flag:</b>", body_style), Paragraph(f"{dom_intel.get('malicious_count', 0)} malicious / {dom_intel.get('total_engines', 90)} engines (Reputation: {dom_intel.get('reputation', 0)})", body_style)],
    ]

    intel_table = Table(intel_geo_rows, colWidths=[2.2 * inch, 5.3 * inch])
    intel_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(intel_table)
    story.append(Spacer(1, 14))

    # 7. Extracted URLs / Hyperlinks Table
    story.append(Paragraph("5. Extracted Links & Defanged URL Forensics", section_heading))
    urls = scan_data.get("extracted_links", {}).get("urls", [])
    
    if not urls:
        story.append(Paragraph("<i>No embedded hyperlinks found in the email body.</i>", body_style))
    else:
        url_rows = [
            [
                Paragraph("<b>Defanged Destination URL</b>", body_style),
                Paragraph("<b>Anchor Text</b>", body_style),
                Paragraph("<b>Security Flags</b>", body_style)
            ]
        ]
        for u in urls[:10]: # cap at 10 in PDF
            flags_str = "<br/>".join([f"• {f}" for f in u.get("flags", [])]) if u.get("flags") else "Clean"
            flags_color = "#dc2626" if u.get("flags") else "#16a34a"
            url_rows.append([
                Paragraph(u.get("defanged_url", ""), code_style),
                Paragraph(u.get("anchor_text", "") or "<i>(No anchor text)</i>", body_style),
                Paragraph(f"<font color='{flags_color}'>{flags_str}</font>", body_style)
            ])

        url_table = Table(url_rows, colWidths=[3.2 * inch, 1.8 * inch, 2.5 * inch])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(url_table)

    # Build document
    doc.build(story)
    return os.path.abspath(pdf_path)
