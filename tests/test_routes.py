import json
import pytest
from app import create_app
from database.db import db
from database.models import User, Analysis


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        # Seed test user
        user = User(username="analyst", email="analyst@mailshield.local", role="admin")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client):
    client.post("/auth/login", data={
        "identifier": "analyst",
        "password": "SecurePass123!"
    }, follow_redirects=True)
    return client


def test_public_routes(client):
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert b"MailShield" in res_index.data

    res_about = client.get("/about")
    assert res_about.status_code == 200
    assert b"System Architecture" in res_about.data


def test_analyze_flow_and_result(auth_client, app):
    res = auth_client.post("/analyze", data={
        "input_mode": "form",
        "sender": "Security Desk <alert@microsoft-phish.xyz>",
        "recipient": "victim@domain.com",
        "subject": "URGENT: Password Reset",
        "body": "Your account will be suspended within 24 hours. Verify your password now: http://login-microsoft-auth.xyz/verify",
        "attachments": "info.pdf"
    }, follow_redirects=True)
    
    assert res.status_code == 200
    assert b"Email Threat Diagnostic Verdict" in res.data
    assert b"PHISHING" in res.data

    with app.app_context():
        analysis = Analysis.query.filter_by(subject="URGENT: Password Reset").first()
        assert analysis is not None
        assert analysis.classification == "PHISHING"
        assert len(analysis.url_analyses) == 1
        assert len(analysis.indicators) > 0


def test_api_analyze_endpoint(client):
    payload = {
        "sender": "service@paypal-verification-center.top",
        "subject": "Account Limited: Confirm Card Details",
        "body": "We restricted your account. Confirm your identity immediately at http://192.168.1.55/paypal/auth.php"
    }
    res = client.post(
        "/api/analyze",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["classification"] == "PHISHING"
    assert data["overall_risk_score"] >= 60.0
    assert len(data["urls"]) == 1


def test_pdf_report_download(auth_client, app):
    # First submit an email
    auth_client.post("/analyze", data={
        "input_mode": "form",
        "sender": "HR Team <hr@company.com>",
        "subject": "Updated Employee Handbook 2026",
        "body": "Please read the updated employee policy guidelines.",
        "attachments": "Handbook.pdf"
    }, follow_redirects=True)

    with app.app_context():
        anl = Analysis.query.first()
        assert anl is not None
        anl_id = anl.id

    res_pdf = auth_client.get(f"/report/{anl_id}/pdf")
    assert res_pdf.status_code == 200
    assert res_pdf.headers["Content-Type"] == "application/pdf"
    assert b"%PDF" in res_pdf.data[:10]
