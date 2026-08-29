import os
from app import create_app
from database.db import db
from database.models import User, Analysis, URLAnalysis, DetectionIndicator
from email_parser.parser import EmailParser
from detector.risk_engine import HybridRiskEngine
from ml.model_manager import ModelManager


def seed_data():
    app = create_app("development")
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin", email="admin@mailshield.local", role="admin")
            admin.set_password("Admin@12345")
            db.session.add(admin)
            db.session.commit()

        # Check if already seeded
        if Analysis.query.count() > 0:
            print("[*] Database already contains analysis records.")
            return

        ml_manager = ModelManager.get_instance(app.config["MODELS_DIR"])

        sample_cases = [
            {
                "sender": "Dr. Alan Miller <a.miller@oxford-academic.edu>",
                "recipient": "students@oxford-academic.edu",
                "subject": "Academic Seminar: AI in Cybersecurity Advances",
                "body": "Dear Department Members, You are cordially invited to attend the guest lecture on 'Machine Learning for Threat Detection' on October 14th in Lecture Hall 3. Refreshments will be served at 10 AM.",
                "attachments": ["Seminar_Schedule.pdf"]
            },
            {
                "sender": "Global Sweepstakes Agent <claims@international-lottery-claims.biz>",
                "recipient": "user@example.com",
                "subject": "CONGRATULATIONS! You Won $1,000,000 in International Lottery!",
                "body": "DEAR BENEFICIARY, YOU HAVE BEEN SELECTED AS THE LUCKY WINNER OF 1,000,000 DOLLARS! 100% free miracle fat burner discount codes and low interest loans instant approval!",
                "attachments": []
            },
            {
                "sender": "Microsoft Security Team <security-alert@login-microsoft-secure-auth.xyz>",
                "recipient": "user@corporate.com",
                "subject": "URGENT: Your Office 365 Account Will Be Suspended Within 24 Hours",
                "body": "Dear User, Your Office 365 password will expire in 24 hours. Failure to update your security credentials immediately will result in account suspension. Click here to verify: http://login-microsoft-secure-auth.xyz/verify",
                "attachments": []
            },
            {
                "sender": "PayPal Support Desk <billing-service@paypal-account-center.top>",
                "recipient": "customer@gmail.com",
                "subject": "Security Alert: Unauthorized Login Detected on Your PayPal Profile",
                "body": "We detected unusual sign-in activity from Russia. To restore account functionality, confirm your credit card and password details immediately: http://192.168.1.105/paypal-auth/resolution.php",
                "attachments": []
            },
            {
                "sender": "Accounting Vendor <remittance@supplier-billing.com>",
                "recipient": "finance@company.com",
                "subject": "Overdue Remittance Notice: Invoice #INV-89218 Attached",
                "body": "Dear Accounts Payable, Please find attached the overdue payment invoice #INV-89218 for immediate processing. Late fees apply after 48 hours.",
                "attachments": ["Invoice_Overdue_August2026.pdf.exe"]
            },
            {
                "sender": "David Miller <david.miller@techcorp.io>",
                "recipient": "sarah@techcorp.io",
                "subject": "Sprint Retrospective & Code Review PR #142",
                "body": "Hi Sarah, The pull request for search endpoint pagination has been reviewed and merged into main branch. All automated CI/CD pipeline tests passed.",
                "attachments": []
            }
        ]

        print("[*] Seeding demonstration email analysis records...")
        for case in sample_cases:
            parsed = EmailParser.parse_input(
                sender=case["sender"],
                recipient=case["recipient"],
                subject=case["subject"],
                body=case["body"],
                attachment_names=case["attachments"]
            )
            result = HybridRiskEngine.evaluate(parsed, ml_manager=ml_manager)

            analysis = Analysis(
                user_id=admin.id,
                sender=result.sender,
                recipient=result.recipient,
                subject=result.subject,
                email_body_snippet=result.body_snippet,
                raw_headers=result.raw_headers,
                spam_score=result.spam_score,
                phishing_score=result.phishing_score,
                url_risk_score=result.url_risk_score,
                sender_risk_score=result.sender_risk_score,
                attachment_risk_score=result.attachment_risk_score,
                header_risk_score=result.header_risk_score,
                html_risk_score=result.html_risk_score,
                overall_risk_score=result.overall_risk_score,
                classification=result.classification,
                risk_level=result.risk_level,
                ml_confidence=result.ml_confidence,
                risk_confidence=result.risk_confidence,
            )
            analysis.recommendations = result.recommendations
            analysis.summary_data = result.summary_data
            db.session.add(analysis)
            db.session.flush()

            if result.url_analysis and result.url_analysis.urls_details:
                for u in result.url_analysis.urls_details:
                    u_rec = URLAnalysis(
                        analysis_id=analysis.id,
                        url=u.url,
                        domain=u.domain,
                        is_https=u.is_https,
                        has_ip=u.has_ip,
                        is_shortener=u.is_shortener,
                        suspicious_tld=u.suspicious_tld,
                        has_punycode=u.has_punycode,
                        has_at_symbol=u.has_at_symbol,
                        subdomain_count=u.subdomain_count,
                        length=u.length,
                        risk_score=u.risk_score,
                    )
                    u_rec.risk_reasons = u.risk_reasons
                    db.session.add(u_rec)

            if result.indicators:
                for ind in result.indicators:
                    ind_rec = DetectionIndicator(
                        analysis_id=analysis.id,
                        category=ind.get("category", "GENERAL"),
                        indicator_name=ind.get("indicator_name", "Flagged Pattern"),
                        description=ind.get("description", ""),
                        severity=ind.get("severity", "MEDIUM"),
                        score_impact=ind.get("score_impact", 0),
                    )
                    db.session.add(ind_rec)

        db.session.commit()
        print(f"[+] Successfully seeded {len(sample_cases)} demonstration email analyses!")


if __name__ == "__main__":
    seed_data()
