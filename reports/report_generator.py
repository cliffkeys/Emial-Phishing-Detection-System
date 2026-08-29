import io
import os
from datetime import datetime
from typing import Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)


def generate_pdf_report(analysis_data: Dict[str, Any], output_stream: Optional[io.BytesIO] = None) -> io.BytesIO:
    """
    Generates a high-quality academic / cybersecurity PDF audit report for an analyzed email.
    """
    if output_stream is None:
        output_stream = io.BytesIO()

    doc = SimpleDocTemplate(
        output_stream,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    primary_color = colors.HexColor("#0f172a")    # Slate dark
    accent_color = colors.HexColor("#2563eb")     # Cyber blue
    text_color = colors.HexColor("#334155")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=primary_color,
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=12,
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=text_color,
    )

    badge_style = ParagraphStyle(
        "BadgeText",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        alignment=1,  # Centered
        textColor=colors.white,
    )

    elements = []

    # 1. Header Banner
    elements.append(Paragraph("MailShield – Threat Detection Security Report", title_style))
    elements.append(Paragraph(
        f"Automated Academic Email Security Analysis | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=accent_color, spaceBefore=2, spaceAfter=10))

    # 2. Executive Summary Banner (Classification & Risk Level)
    classification = analysis_data.get("classification", "SAFE")
    risk_level = analysis_data.get("risk_level", "LOW")
    risk_score = analysis_data.get("overall_risk_score", 0.0)
    ml_conf = analysis_data.get("ml_confidence", 0.0)

    # Color code classification
    if classification == "PHISHING":
        bg_banner = colors.HexColor("#dc2626")  # Red
    elif classification == "SPAM":
        bg_banner = colors.HexColor("#ea580c")  # Orange
    elif classification == "SUSPICIOUS":
        bg_banner = colors.HexColor("#d97706")  # Amber
    else:
        bg_banner = colors.HexColor("#16a34a")  # Green

    summary_banner_data = [
        [
            Paragraph(f"<b>FINAL CLASSIFICATION: {classification}</b>", badge_style),
            Paragraph(f"<b>RISK LEVEL: {risk_level}</b>", badge_style),
            Paragraph(f"<b>RISK SCORE: {risk_score} / 100</b>", badge_style),
            Paragraph(f"<b>ML CONFIDENCE: {ml_conf}%</b>", badge_style),
        ]
    ]
    summary_table = Table(summary_banner_data, colWidths=[135, 135, 135, 135])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_banner),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("CORNERPAD", (0, 0), (-1, -1), 4),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # 3. Email Metadata Section
    elements.append(Paragraph("Email Metadata", section_heading))
    meta_rows = [
        [Paragraph("<b>Sender (From):</b>", body_style), Paragraph(str(analysis_data.get("sender", "N/A")), body_style)],
        [Paragraph("<b>Recipient (To):</b>", body_style), Paragraph(str(analysis_data.get("recipient", "N/A") or "N/A"), body_style)],
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(str(analysis_data.get("subject", "N/A")), body_style)],
        [Paragraph("<b>Analysis ID:</b>", body_style), Paragraph(f"MS-ANL-{analysis_data.get('id', 'N/A')}", body_style)],
    ]
    meta_table = Table(meta_rows, colWidths=[120, 420])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 10))

    # 4. Multi-Vector Scoring Breakdown
    elements.append(Paragraph("Multi-Vector Diagnostic Sub-Scores", section_heading))
    scores_data = [
        [
            Paragraph("<b>Vector</b>", body_style),
            Paragraph("<b>Diagnostic Score</b>", body_style),
            Paragraph("<b>Risk Status</b>", body_style)
        ],
        [
            Paragraph("Machine Learning Spam Probability", body_style),
            Paragraph(f"{analysis_data.get('spam_score', 0.0)}%", body_style),
            Paragraph("Elevated" if analysis_data.get('spam_score', 0.0) >= 50 else "Nominal", body_style)
        ],
        [
            Paragraph("Phishing Linguistic Heuristics", body_style),
            Paragraph(f"{analysis_data.get('phishing_score', 0.0)} / 100", body_style),
            Paragraph("Severe" if analysis_data.get('phishing_score', 0.0) >= 60 else "Elevated" if analysis_data.get('phishing_score', 0.0) >= 30 else "Nominal", body_style)
        ],
        [
            Paragraph("URL Structural & Reputation Risk", body_style),
            Paragraph(f"{analysis_data.get('url_risk_score', 0.0)} / 100", body_style),
            Paragraph("Severe" if analysis_data.get('url_risk_score', 0.0) >= 60 else "Elevated" if analysis_data.get('url_risk_score', 0.0) >= 30 else "Nominal", body_style)
        ],
        [
            Paragraph("Sender Spoofing & Identity Risk", body_style),
            Paragraph(f"{analysis_data.get('sender_risk_score', 0.0)} / 100", body_style),
            Paragraph("Severe" if analysis_data.get('sender_risk_score', 0.0) >= 60 else "Elevated" if analysis_data.get('sender_risk_score', 0.0) >= 30 else "Nominal", body_style)
        ],
        [
            Paragraph("Attachment Payload Risk", body_style),
            Paragraph(f"{analysis_data.get('attachment_risk_score', 0.0)} / 100", body_style),
            Paragraph("Severe" if analysis_data.get('attachment_risk_score', 0.0) >= 50 else "Nominal", body_style)
        ],
        [
            Paragraph("Header Authentication Verdict", body_style),
            Paragraph(str(analysis_data.get('header_risk_score', 0.0)), body_style),
            Paragraph(str(analysis_data.get('auth_summary', 'Not available')), body_style)
        ],
    ]
    scores_table = Table(scores_data, colWidths=[240, 120, 180])
    scores_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(scores_table)
    elements.append(Spacer(1, 10))

    # 5. Detected Indicators & Specific Findings
    indicators = analysis_data.get("indicators", [])
    if indicators:
        elements.append(Paragraph(f"Detected Security Indicators ({len(indicators)})", section_heading))
        ind_rows = [
            [
                Paragraph("<b>Category</b>", body_style),
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Finding & Technical Description</b>", body_style)
            ]
        ]
        for ind in indicators[:8]:  # Limit top 8 for clean page fit
            sev = ind.get("severity", "MEDIUM")
            ind_rows.append([
                Paragraph(ind.get("category", "General"), body_style),
                Paragraph(f"<b>{sev}</b>", body_style),
                Paragraph(f"<b>{ind.get('indicator_name', '')}</b>: {ind.get('description', '')}", body_style)
            ])
        ind_table = Table(ind_rows, colWidths=[100, 70, 370])
        ind_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(ind_table)
        elements.append(Spacer(1, 10))

    # 6. Actionable Recommendations
    elements.append(Paragraph("Actionable Security Recommendations", section_heading))
    recs = analysis_data.get("recommendations", [])
    if not recs:
        recs = ["No critical action required. Continue observing standard cybersecurity hygiene."]
    
    rec_items = []
    for r in recs:
        rec_items.append([Paragraph("•", body_style), Paragraph(f"<b>{r}</b>", body_style)])
    
    rec_table = Table(rec_items, colWidths=[15, 525])
    rec_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    elements.append(rec_table)
    elements.append(Spacer(1, 12))

    # 7. Academic Footer & Disclaimer
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph(
        "<i>Disclaimer: This report is generated by the MailShield Academic Email Spam & Phishing Detection System. "
        "Threat assessments combine natural language processing, lexical URL analysis, and multi-vector heuristic scoring. "
        "For mission-critical environments, verify indicators with an enterprise security operations team.</i>",
        subtitle_style
    ))

    # Build document
    doc.build(elements)
    output_stream.seek(0)
    return output_stream
