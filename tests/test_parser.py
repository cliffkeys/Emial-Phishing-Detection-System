import pytest
from email_parser.parser import EmailParser


def test_parse_form_fields():
    parsed = EmailParser.parse_input(
        sender="Security Team <security@example.com>",
        recipient="target@company.com",
        subject="Password Reset Request",
        body="Please click here: http://secure-auth.xyz/reset to change your password.",
        attachment_names=["manual.pdf", "script.exe"]
    )

    assert parsed.sender_email == "security@example.com"
    assert parsed.sender_name == "Security Team"
    assert parsed.sender_domain == "example.com"
    assert parsed.recipient_email == "target@company.com"
    assert parsed.subject == "Password Reset Request"
    assert len(parsed.urls) == 1
    assert "http://secure-auth.xyz/reset" in parsed.urls
    assert len(parsed.attachments) == 2
    assert parsed.attachments[0]["extension"] == ".pdf"
    assert parsed.attachments[1]["extension"] == ".exe"


def test_parse_raw_rfc822_email():
    raw_email = """From: "Bank of America Support" <alerts@bofa-security-auth.top>
To: customer@victim.com
Subject: Action Required: Your Online Access is Restricted
Date: Mon, 15 Jun 2026 10:00:00 +0000
Message-ID: <123456789.bofa@alert.top>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Authentication-Results: spf=fail (sender IP not authorized); dkim=fail; dmarc=fail

<html>
<body>
<p>Your bank card has been suspended. <a href="http://192.168.1.50/bofa/login.php">Click here to verify</a>.</p>
</body>
</html>"""

    parsed = EmailParser.parse_input(raw_email=raw_email)
    assert parsed.is_raw_rfc822 is True
    assert parsed.sender_name == "Bank of America Support"
    assert parsed.sender_email == "alerts@bofa-security-auth.top"
    assert parsed.sender_domain == "bofa-security-auth.top"
    assert parsed.subject == "Action Required: Your Online Access is Restricted"
    assert len(parsed.urls) == 1
    assert "http://192.168.1.50/bofa/login.php" in parsed.urls
    assert "spf=fail" in parsed.auth_results_raw


def test_malformed_email_graceful_handling():
    malformed_input = "This is completely malformed text without RFC headers"
    parsed = EmailParser.parse_input(raw_email=malformed_input)
    assert parsed.full_text != ""
    assert parsed.subject == "No Subject"
