import pytest
from email_parser.parser import EmailParser
from detector.risk_engine import HybridRiskEngine


def test_legitimate_email_classification():
    parsed = EmailParser.parse_input(
        sender="Dr. Michael Scott <mscott@dundermifflin.com>",
        recipient="staff@dundermifflin.com",
        subject="Department Strategy Meeting - Tuesday 10 AM",
        body="Good morning all, Please review the attached agenda for our strategy meeting on Tuesday. We will discuss Q3 goals.",
        attachment_names=["agenda.docx"]
    )
    result = HybridRiskEngine.evaluate(parsed)
    assert result.classification == "SAFE"
    assert result.risk_level == "LOW"
    assert result.overall_risk_score < 30.0


def test_phishing_credential_email_classification():
    parsed = EmailParser.parse_input(
        sender="Microsoft Office 365 <support@auth-verify-365.xyz>",
        recipient="user@victim.com",
        subject="URGENT: Your mailbox will be deactivated in 24 hours",
        body="Immediate action required. Your password has expired. Click here to confirm your identity: http://login-microsoft-secure-auth.xyz/verify",
        attachment_names=[]
    )
    result = HybridRiskEngine.evaluate(parsed)
    assert result.classification == "PHISHING"
    assert result.risk_level in ("HIGH", "CRITICAL")
    assert result.overall_risk_score >= 60.0
    assert len(result.recommendations) > 0


def test_promotional_spam_classification():
    parsed = EmailParser.parse_input(
        sender="Deals Online <sales@clearance-super-blast.biz>",
        recipient="user@victim.com",
        subject="CONGRATULATIONS! You Won $1,000,000 in International Lottery!",
        body="Claim your 1,000,000 dollars cash prize immediately! 100% free miracle fat loss pills and low interest loans no credit check!",
        attachment_names=[]
    )
    result = HybridRiskEngine.evaluate(parsed)
    assert result.classification in ("SPAM", "SUSPICIOUS")
    assert result.spam_score > 0.0


def test_malicious_executable_attachment_escalation():
    parsed = EmailParser.parse_input(
        sender="Accounting <billing@vendor.com>",
        recipient="finance@company.com",
        subject="Overdue Remittance Invoice",
        body="Please find your remittance statement attached.",
        attachment_names=["Invoice_Aug2026.pdf.exe"]
    )
    result = HybridRiskEngine.evaluate(parsed)
    assert result.overall_risk_score >= 80.0
    assert result.risk_level == "CRITICAL"
