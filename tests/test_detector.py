import pytest
from detector.text_analyzer import TextAnalyzer
from detector.sender_analyzer import SenderAnalyzer
from detector.attachment_analyzer import AttachmentAnalyzer
from detector.header_analyzer import HeaderAnalyzer
from detector.html_analyzer import HTMLAnalyzer


def test_text_analyzer_phishing_keywords():
    text = "URGENT: Your account will be suspended within 24 hours. Please verify your password immediately."
    res = TextAnalyzer.analyze_text(text)
    assert res.phishing_score >= 50.0
    assert "URGENCY" in res.matched_categories
    assert "CREDENTIALS" in res.matched_categories


def test_text_analyzer_clean_business_text():
    text = "Hi Team, Let's meet on Friday at 2 PM to review the quarterly roadmap and Gantt chart deliverables."
    res = TextAnalyzer.analyze_text(text)
    assert res.phishing_score == 0.0
    assert res.spam_text_score == 0.0


def test_sender_brand_spoofing():
    res = SenderAnalyzer.analyze_sender(
        sender_raw="Microsoft Account Team <security@fake-support-login.com>",
        reply_to_raw="attacker@stealth-inbox.net"
    )
    assert res.is_spoofed_display_name is True
    assert res.is_reply_to_mismatch is True
    assert res.sender_risk_score >= 60.0


def test_attachment_weaponized_extension():
    attachments = [
        {"filename": "Invoice_Aug2026.pdf.exe"},
        {"filename": "Payroll_Macro.docm"}
    ]
    res = AttachmentAnalyzer.analyze_attachments(attachments)
    assert res.attachment_risk_score >= 50.0
    assert res.attachments_details[0].is_double_extension is True
    assert res.attachments_details[0].is_executable is True
    assert res.attachments_details[1].is_macro_enabled is True


def test_header_analyzer_spf_dkim_failures():
    raw_auth = "Authentication-Results: spf=fail (IP not authorized); dkim=fail; dmarc=fail"
    res = HeaderAnalyzer.analyze_headers(raw_headers=raw_auth)
    assert res.spf_status == "Fail"
    assert res.dkim_status == "Fail"
    assert res.dmarc_status == "Fail"
    assert res.header_risk_score >= 60.0


def test_html_deceptive_link_mismatch():
    html_links = [
        {"text": "https://paypal.com/signin", "href": "http://evil-phishing-site.xyz/login"}
    ]
    res = HTMLAnalyzer.analyze_html(html_links=html_links)
    assert res.html_risk_score >= 45.0
    assert len(res.deceptive_links) == 1
